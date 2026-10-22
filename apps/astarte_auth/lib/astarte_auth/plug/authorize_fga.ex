#
# This file is part of Astarte.
#
# Copyright 2026 SECO Mind Srl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule Astarte.Auth.Plug.AuthorizeFGA do
  @moduledoc """
  A Plug to authorize requests using OpenFGA.

  Requires the user to be authenticated and available in Guardian context.
  Takes options to define which relation to check and what the target object is.

  ## Options
  * `:relation` - Required. Either a string or a function `(conn -> String.t())`.
  * `:target` - Required. Atom representing the target type (e.g. `:realm`, `:interface`, `:device`).
  * `:target_id_param` - Optional. String representing the path parameter to use as the ID of the target object. Required if `:target` is not `:realm`.
  """
  import Plug.Conn
  require Logger

  alias Astarte.Auth.OpenFGA

  def init(opts) do
    relation = Keyword.fetch!(opts, :relation)
    target = Keyword.fetch!(opts, :target)
    target_id_param = Keyword.get(opts, :target_id_param)

    if target != :realm and is_nil(target_id_param) do
      raise ArgumentError, "target_id_param is required when target is not :realm"
    end

    %{
      relation: relation,
      target: target,
      target_id_param: target_id_param
    }
  end

  def call(conn, %{relation: relation_opt, target: target, target_id_param: target_id_param}) do
    # Assuming the guardian plug has run and stored the resource in assigns
    user_id = get_user_id(conn)
    realm = conn.path_params["realm_name"]

    if is_nil(realm) do
      Logger.warning("FGA Check: Missing realm in connection.",
        tag: "fga_unauthorized"
      )

      unauthorized(conn)
    else
      relation =
        if is_function(relation_opt) do
          relation_opt.(conn)
        else
          relation_opt
        end

      object_id =
        if target == :realm do
          realm
        else
          conn.path_params[target_id_param]
        end

      if is_nil(object_id) do
        Logger.warning("FGA Check: Missing target_id_param #{target_id_param} in path.",
          tag: "fga_unauthorized"
        )

        unauthorized(conn)
      else
        object = "#{target}:#{realm}/#{object_id}"
        # For realm target, it's just realm:<realm>
        object = if target == :realm, do: "realm:#{realm}", else: object

        # We prefix the user id with user:<realm>/
        user = "user:#{realm}/#{user_id}"

        contextual_tuples = build_contextual_tuples(conn, user_id, realm)

        case OpenFGA.check(user, relation, object, contextual_tuples) do
          :ok ->
            conn

          {:error, :forbidden} ->
            Logger.info("FGA Check: user #{user} denied relation #{relation} on #{object}",
              tag: "fga_forbidden"
            )

            forbidden(conn)

          {:error, reason} ->
            Logger.error("FGA Check failed: #{inspect(reason)}", tag: "fga_error")

            conn
            |> send_resp(500, Jason.encode!(%{errors: %{detail: "Internal Server Error"}}))
            |> halt()
        end
      end
    end
  end

  defp build_contextual_tuples(conn, user_id, realm_name) do
    Enum.map(get_roles(conn), fn role ->
      %{
        user: "user:#{realm_name}/#{user_id}",
        relation: role,
        object: "realm:#{realm_name}"
      }
    end)
  end

  defp get_roles(conn) do
    roles =
      case Guardian.Plug.current_resource(conn) do
        %{roles: r} when is_list(r) -> r
        %{"roles" => r} when is_list(r) -> r
        _ ->
          case Guardian.Plug.current_claims(conn) do
            %{"roles" => r} when is_list(r) -> r
            _ -> []
          end
      end

    Enum.reject(roles, fn role -> is_nil(role) or String.trim(role) == "" end)
  end

  defp get_user_id(conn) do
    # Standard fallback looking at standard guardian resource locations
    case Guardian.Plug.current_resource(conn) do
      %{id: id} when not is_nil(id) -> id
      %{subject: id} when not is_nil(id) -> id
      _ -> "astarte_system"
    end
  end

  defp unauthorized(conn) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(%{errors: %{detail: "Unauthorized"}}))
    |> halt()
  end

  defp forbidden(conn) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(403, Jason.encode!(%{errors: %{detail: "Forbidden"}}))
    |> halt()
  end
end
