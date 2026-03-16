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

  @type cose_alg :: :es256 | :es384 | :ps256 | :rs256 | :rs384

  @doc """
  Sign data using a key stored in OpenBao's transit engine.
  Translates FDO/COSE algorithms to the specific OpenBao parameters.
  """
  @spec sign(String.t(), binary(), cose_alg(), String.t() | nil, String.t() | nil) ::
          {:ok, binary()} | :error
  def sign(key_name, payload, alg, auth_token, namespace \\ nil) do
    # Map the COSE algorithm to specific OpenBao options
    vault_opts = map_cose_alg_to_vault_opts(alg)

    hash_alg = Keyword.fetch!(vault_opts, :hash_algorithm)
    url_path = "/v1/transit/sign/#{key_name}/#{hash_alg}"

    # Build the JSON payload
    body_map = %{input: Base.encode64(payload)}

    body_map =
      if sig_algo = Keyword.get(vault_opts, :signature_algorithm),
        do: Map.put(body_map, :signature_algorithm, sig_algo),
        else: body_map

    marshaling = Keyword.get(vault_opts, :marshaling_algorithm)

    body_map =
      if marshaling, do: Map.put(body_map, :marshaling_algorithm, marshaling), else: body_map

    req_body = Jason.encode!(body_map)

    # Set headers (including the optional namespace)
    # TODO: Check if the namespace should be set in the Client configuration
    headers = build_custom_headers(auth_token)
    headers = if namespace, do: [{"X-Vault-Namespace", namespace} | headers], else: headers

    # Perform the HTTP call
    case Client.post(url_path, req_body, headers) do
      {:ok, %HTTPoison.Response{status_code: 200, body: resp_body}} ->
        with {:ok, decoded} <- Jason.decode(resp_body),
             vault_sig when is_binary(vault_sig) <- get_in(decoded, ["data", "signature"]),
             # OpenBao signature format: "vault:v1:BASE64_STRING"
             [_, _, b64_sig] <- String.split(vault_sig, ":", parts: 3),
             # Decode based on the requested marshaling type
             {:ok, raw_sig} <- decode_vault_sig(b64_sig, marshaling) do
          {:ok, raw_sig}
        else
          _ ->
            Logger.error("Failed to parse or decode signature from Vault response")
            :error
        end

      error_resp ->
        Logger.error("Encountered HTTP error during signing: #{inspect(error_resp)}")
        :error
    end
  end

  # Decodes the Base64 signature returned by OpenBao.
  # When using the "jws" marshaling algorithm, OpenBao returns a URL-safe Base64 string without padding.
  defp decode_vault_sig(b64_sig, "jws") do
    Base.url_decode64(b64_sig, padding: false)
  end

  # For "asn1" or default marshaling, OpenBao uses standard Base64 encoding.
  defp decode_vault_sig(b64_sig, _other) do
    Base.decode64(b64_sig)
  end

  # Translates Astarte/COSE supported algorithms into OpenBao Transit engine parameters.
  defp map_cose_alg_to_vault_opts(:es256) do
    [hash_algorithm: "sha2-256", marshaling_algorithm: "jws"]
  end

  defp map_cose_alg_to_vault_opts(:es384) do
    [hash_algorithm: "sha2-384", marshaling_algorithm: "jws"]
  end

  defp map_cose_alg_to_vault_opts(:ps256) do
    [hash_algorithm: "sha2-256", signature_algorithm: "pss"]
  end

  defp map_cose_alg_to_vault_opts(:rs256) do
    [hash_algorithm: "sha2-256", signature_algorithm: "pkcs1v15"]
  end

  defp map_cose_alg_to_vault_opts(:rs384) do
    [hash_algorithm: "sha2-384", signature_algorithm: "pkcs1v15"]
  end
end
