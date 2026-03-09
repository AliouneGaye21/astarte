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

defmodule Astarte.Pairing.FDO.OpenBao.Core do
  @moduledoc """
  Implementation of function to interface with OpenBao.
  """

  alias Astarte.Pairing.FDO.OpenBao.Client

  require Logger

  @type key_algorithm :: :ec256 | :ec384 | :rsa2048 | :rsa3072

  @spec key_type_to_string(key_algorithm()) :: {:ok, String.t()} | :error
  def key_type_to_string(key_type) do
    case key_type do
      :ec256 -> {:ok, "ecdsa-p256"}
      :ec384 -> {:ok, "ecdsa-p384"}
      :rsa2048 -> {:ok, "rsa-2048"}
      :rsa3072 -> {:ok, "rsa-3072"}
      _ -> :error
    end
  end

  @spec create_keypair(String.t(), String.t(), boolean(), String.t() | nil) ::
          :error | {:error, Jason.DecodeError.t()} | {:ok, any()}
  def create_keypair(key_name, key_type, allow_key_export_and_backup, auth_token) do
    req_body =
      %{
        type: key_type,
        exportable: allow_key_export_and_backup,
        allow_plaintext_backup: allow_key_export_and_backup
      }
      |> Jason.encode!()

    headers = build_custom_headers(auth_token)

    case Client.post("/v1/transit/keys/#{key_name}", req_body, headers) do
      {:ok, %HTTPoison.Response{status_code: 200, body: resp_body}} ->
        with {:ok, decoded_resp_body} <- Jason.decode(resp_body) do
          Map.fetch(decoded_resp_body, "data")
        end

      error_resp ->
        Logger.error("Encountered HTTP error #{inspect(error_resp)}")
        :error
    end
  end

  # custom headers to properly interact with OpenBao
  @spec build_custom_headers(String.t() | nil) :: list()
  def build_custom_headers(custom_token) do
    base_header = [{"Content-Type", "application/json"}]

    case custom_token do
      nil -> base_header
      token -> [{"X-Vault-Token", token} | base_header]
    end
  end
end
