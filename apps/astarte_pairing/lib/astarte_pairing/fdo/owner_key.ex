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

defmodule Astarte.Pairing.FDO.OwnerKey do
  @moduledoc """
  Owner key lookups shared by the REST controllers and the GraphQL resolvers.

  Key algorithms are given as the secrets store names them, e.g. `"ecdsa-p256"`.
  """

  alias Astarte.Secrets

  @doc """
  Lists the realm's owner key names, grouped by key algorithm.
  """
  @spec list(String.t()) :: {:ok, map()} | term()
  def list(realm_name) do
    Secrets.Core.get_keys(realm_name, Secrets.Core.asymmetric_key_algorithms())
  end

  @doc """
  Lists the realm's owner key names for one key algorithm.

  Returns `:error` if the key algorithm is unknown.
  """
  @spec list(String.t(), String.t()) :: {:ok, map()} | term()
  def list(realm_name, key_algorithm) do
    with {:ok, algorithm} <- Secrets.Core.string_to_key_type(key_algorithm) do
      Secrets.Core.get_keys(realm_name, [algorithm])
    end
  end

  @doc """
  Fetches the owner key named `key_name`.

  Returns `:error` if the key algorithm is unknown, or `:not_found` if the realm
  has no such key.
  """
  @spec fetch(String.t(), String.t(), String.t()) :: {:ok, struct()} | :error | :not_found
  def fetch(realm_name, key_algorithm, key_name) do
    with {:ok, algorithm} <- Secrets.Core.string_to_key_type(key_algorithm) do
      Secrets.Core.find_key(realm_name, key_name, algorithm)
    end
  end
end
