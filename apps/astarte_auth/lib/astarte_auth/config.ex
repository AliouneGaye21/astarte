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

defmodule Astarte.Auth.Config do
  @moduledoc """
  Configuration of the authorization services shared by every Astarte service.

  OpenFGA is a single cluster-wide deployment, so it is configured here once
  instead of once per service: every service reads the same `ASTARTE_OPENFGA_*`
  environment variables.
  """

  use Astarte.Config, env_app: "ASTARTE"

  alias Astarte.Auth.OpenFGA

  url_env :openfga, :astarte_auth, :openfga, default_port: 8080, env_app: "ASTARTE"

  @envdoc """
  The OpenFGA store id to use for authorization checks. When unset, the store
  is looked up by `ASTARTE_OPENFGA_STORE_NAME` at startup.
  """
  app_env :openfga_store_id, :astarte_auth, :openfga_store_id,
    os_env: "ASTARTE_OPENFGA_STORE_ID",
    type: :binary

  @envdoc """
  The name of the OpenFGA store to use when `ASTARTE_OPENFGA_STORE_ID` is
  unset. Exactly one store must have this name.
  """
  app_env :openfga_store_name, :astarte_auth, :openfga_store_name,
    os_env: "ASTARTE_OPENFGA_STORE_NAME",
    type: :binary

  @doc """
  Makes sure an OpenFGA store id is configured before the first
  authorization check, looking it up by `openfga_store_name` if needed.

  Raises if neither is set or the store can't be found, so a misconfigured
  service stops at startup.
  """
  def init! do
    store_id = store_id!(openfga_store_id!(), openfga_store_name!())
    :ok = put_openfga_store_id(store_id)
  end

  @doc false
  # The store id init!/0 settles on, given the configured id and name. Kept
  # apart from init!/0 so it can be tested without stubbing the configuration.
  def store_id!(store_id, _store_name) when store_id not in [nil, ""], do: store_id

  def store_id!(_store_id, store_name) when store_name in [nil, ""],
    do: raise("Either ASTARTE_OPENFGA_STORE_ID or ASTARTE_OPENFGA_STORE_NAME must be set.")

  def store_id!(_store_id, store_name) do
    case OpenFGA.fetch_store_id(store_name) do
      {:ok, store_id} ->
        store_id

      {:error, reason} ->
        raise "Couldn't find the OpenFGA store named #{inspect(store_name)}: #{inspect(reason)}."
    end
  end
end
