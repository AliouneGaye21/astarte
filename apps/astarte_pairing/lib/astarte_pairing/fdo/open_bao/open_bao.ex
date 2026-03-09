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

defmodule Astarte.Pairing.FDO.OpenBao do
  @moduledoc """
  Functionality to interface with OpenBao APIs.
  """

  alias Astarte.Pairing.FDO.OpenBao.{Client, Core}

  require Logger

  @spec create_keypair(String.t(), Core.key_algorithm(), list()) ::
          {:ok, map()} | {:error, Jason.DecodeError.t()} | :error
  def create_keypair(key_name, key_type, opts \\ []) do
    allow_key_export_and_backup = Keyword.get(opts, :allow_key_export_and_backup, false)
    auth_token = Keyword.get(opts, :auth_token, nil)

    with {:ok, key_type_string} <- Core.key_type_to_string(key_type) do
      Core.create_keypair(key_name, key_type_string, allow_key_export_and_backup, auth_token)
    end
  end

  @spec enable_key_deletion(String.t()) :: {:ok, map()} | :error
  def enable_key_deletion(key_name, opts \\ []) do
    auth_token = Keyword.get(opts, :auth_token, nil)

    req_body = %{deletion_allowed: true} |> Jason.encode!()

    headers = Core.build_custom_headers(auth_token)

    case Client.post("/v1/transit/keys/#{key_name}/config", req_body, headers) do
      {:ok, %HTTPoison.Response{status_code: 200}} ->
        {:ok, %{}}

      error_resp ->
        Logger.error("Encountered HTTP error #{inspect(error_resp)}")
        :error
    end
  end

  @spec delete_key(String.t()) :: {:ok, map()} | :error
  def delete_key(key_name, opts \\ []) do
    auth_token = Keyword.get(opts, :auth_token, nil)

    headers = Core.build_custom_headers(auth_token)

    case Client.delete("/v1/transit/keys/#{key_name}", headers) do
      {:ok, %HTTPoison.Response{status_code: 204}} ->
        {:ok, %{}}

      error_resp ->
        Logger.error("Encountered HTTP error #{inspect(error_resp)}")
        :error
    end
  end
end
