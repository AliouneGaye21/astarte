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

defmodule Astarte.Auth.GraphQL.Middleware.AuthorizeFGA do
  @moduledoc """
  Absinthe middleware that authorizes GraphQL field resolution against
  OpenFGA, unless authentication is disabled.

  It reads the identity and the realm from the Absinthe context built by
  `Astarte.Auth.GraphQL.Plug.Context`, and checks `relation` on the object
  named by `target`:

  ```elixir
  field :list_owner_keys, :owner_keys_map do
    middleware AuthorizeFGA, relation: "fdo_read", target: :realm
    resolve &FdoResolver.list_owner_keys/3
  end
  ```

  `target` accepts:

  - `:realm` - checks against `realm:<realm from the context>`.
  - `:device` - checks against `device:<the field's `hw_id` argument>`.
  - `{type, arg}` - checks against `<type>:<the field's `arg` argument>`, for
    any other object type in the authorization model, e.g.
    `{:interface, :interface_name}`.

  Authorization fails closed: a field whose object cannot be identified (the
  context carries no realm, or the naming argument is missing) is rejected
  rather than checked against a guessed object.
  """

  @behaviour Absinthe.Middleware

  alias Astarte.Auth.OpenFGA

  require Logger

  @impl Absinthe.Middleware
  def call(resolution, opts) do
    do_authorize(resolution, opts)
  end

  defp do_authorize(resolution, opts) do
    context = resolution.context

    relation = Keyword.fetch!(opts, :relation)
    target = Keyword.fetch!(opts, :target)

    realm_name = Map.get(context, :realm_name)

    with {:ok, user_id} <- user_id(context),
         {:ok, object} <- object(target, realm_name, resolution.arguments) do
      Logger.debug("Authorizing user #{inspect(user_id)} for #{relation} on #{object}")

      contextual_tuples = build_contextual_tuples(context, user_id, realm_name, target, object)

      "user:#{user_id}"
      |> OpenFGA.check(relation, object, contextual_tuples)
      |> handle_check_result(resolution)
    else
      {:error, message} -> unauthorized(resolution, message)
    end
  end

  defp build_contextual_tuples(context, user_id, realm_name, target, object) do
    # Extract roles from the current user in the context.
    # Assume that AuthGuardian or the JWT mapping stored a :roles field
    # as a list of strings: e.g. ["admin", "user"]
    roles =
      if realm_name do
        Enum.map(get_roles(context), fn role ->
          %{
            user: "user:#{user_id}",
            relation: role,
            object: "realm:#{realm_name}"
          }
        end)
      else
        # If there is no realm_name in the context, this is a cluster-level request
        # (e.g. Housekeeping). The roles in the token apply to the cluster.
        Enum.map(get_roles(context), fn role ->
          %{
            user: "user:#{user_id}",
            relation: role,
            object: "cluster:astarte"
          }
        end)
      end

    object_tuple =
      cond do
        not is_nil(realm_name) and target != :realm and target != :cluster and not match?({:realm, _}, target) ->
          # Indicate that the requested object belongs to this realm
          [
            %{
              user: "realm:#{realm_name}",
              relation: "realm",
              object: object
            }
          ]

        is_nil(realm_name) and match?({:realm, _}, target) ->
          # Indicate that the requested realm belongs to the cluster
          [
            %{
              user: "cluster:astarte",
              relation: "parent",
              object: object
            }
          ]

        true ->
          []
      end

    roles ++ object_tuple
  end

  defp get_roles(context) do
    case Map.get(context, :current_user) do
      %{roles: roles} when is_list(roles) -> roles
      %{"roles" => roles} when is_list(roles) -> roles
      _ -> []
    end
  end

  defp handle_check_result(:ok, resolution), do: resolution

  defp handle_check_result({:error, :forbidden}, resolution),
    do: unauthorized(resolution, "Forbidden: OpenFGA denied access for this action")

  defp handle_check_result({:error, :store_not_configured}, resolution),
    do: unauthorized(resolution, "Authorization unavailable: OpenFGA store not configured")

  defp handle_check_result({:error, reason}, resolution) do
    Logger.error("OpenFGA check failed: #{inspect(reason)}")
    unauthorized(resolution, "Internal Server Error during authorization")
  end

  defp unauthorized(resolution, message),
    do: Absinthe.Resolution.put_result(resolution, {:error, message})

  # current_user is the user struct Guardian loaded from the JWT (its id is the
  # "sub" claim), or nil when there was no valid token. Anything else is
  # rejected instead of guessing an identity.
  defp user_id(context) do
    case Map.get(context, :current_user) do
      %{id: id} when not is_nil(id) -> {:ok, id}
      _ -> {:error, "Unauthorized: Missing valid user session"}
    end
  end

  # Every Astarte GraphQL request is realm-scoped, so a request without a realm
  # is rejected whatever its target object is, unless it's a cluster-level operation.
  defp object(:cluster, _realm_name, _arguments), do: {:ok, "cluster:astarte"}

  defp object(:realm, realm_name, _arguments) when not is_nil(realm_name), do: {:ok, "realm:#{realm_name}"}
  defp object(:realm, nil, _arguments), do: {:error, "Unauthorized: Missing realm context"}

  defp object(:device, realm_name, arguments),
    do: object({:device, :hw_id}, realm_name, arguments)

  defp object(:interface, realm_name, arguments),
    do: object({:interface, :interface_name}, realm_name, arguments)

  defp object(:trigger, realm_name, arguments),
    do: object({:trigger, :trigger_name}, realm_name, arguments)

  defp object(:trigger_policy, realm_name, arguments),
    do: object({:trigger_policy, :policy_name}, realm_name, arguments)

  defp object({type, arg}, realm_name, arguments) do
    case Map.get(arguments, arg) do
      nil ->
        Logger.warning("AuthorizeFGA: a #{inspect(type)}-target field was called without #{arg}")

        {:error, "Forbidden: OpenFGA denied access for this action"}

      id ->
        if type == :realm do
          {:ok, "realm:#{id}"}
        else
          if is_nil(realm_name) do
            {:error, "Unauthorized: Missing realm context"}
          else
            {:ok, "#{type}:#{realm_name}/#{id}"}
          end
        end
    end
  end
end
