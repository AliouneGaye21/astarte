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

defmodule Astarte.PairingWeb.GraphQL.Resolvers.FdoResolver do
  @moduledoc """
  Absinthe resolvers for FDO-related GraphQL fields: owner key management
  and ownership voucher operations.
  """

  alias Astarte.FDO.OwnershipVoucher
  alias Astarte.Pairing.FDO
  alias Astarte.Pairing.FDO.OwnerKey
  alias Astarte.PairingWeb.ChangesetView
  alias Astarte.PairingWeb.OwnershipVoucherView
  alias Astarte.Secrets.OwnerKeyInitialization
  alias Astarte.Secrets.OwnerKeyInitializationOptions

  def list_owner_keys(_parent, %{key_algorithm: alg}, %{context: %{realm_name: realm}})
      when is_binary(alg) do
    realm
    |> OwnerKey.list(alg)
    |> owner_keys_result()
  end

  def list_owner_keys(_parent, _args, %{context: %{realm_name: realm}}) do
    realm
    |> OwnerKey.list()
    |> owner_keys_result()
  end

  def get_owner_key(_parent, %{key_algorithm: alg, key_name: key_name}, %{
        context: %{realm_name: realm}
      }) do
    case OwnerKey.fetch(realm, alg, key_name) do
      {:ok, key} -> {:ok, %{key_name: key.name, public_key: key.public_pem}}
      :error -> {:error, "Invalid key algorithm"}
      :not_found -> {:error, "Key not found"}
    end
  end

  def create_or_upload_owner_key(_parent, args, %{context: %{realm_name: realm}}) do
    changeset = OwnerKeyInitializationOptions.changeset(%OwnerKeyInitializationOptions{}, args)

    with {:ok, validated_options} <- validate_owner_key_options(changeset) do
      OwnerKeyInitialization.create_or_upload(validated_options, realm)
    end
  end

  defp validate_owner_key_options(changeset) do
    case Ecto.Changeset.apply_action(changeset, :insert) do
      {:ok, validated_options} -> {:ok, validated_options}
      {:error, changeset} -> changeset_error(changeset)
    end
  end

  def owner_keys_for_voucher(_parent, %{ownership_voucher: pem}, %{context: %{realm_name: realm}}) do
    realm
    |> FDO.OwnershipVoucher.compatible_owner_keys(pem)
    |> owner_keys_result()
  end

  # The secrets store reports some failures as a bare :error, which Absinthe
  # can't render.
  defp owner_keys_result(:error), do: {:error, "Failed to list the owner keys"}
  defp owner_keys_result(result), do: result

  def list_ownership_vouchers(_parent, _args, %{context: %{realm_name: realm}}) do
    with {:ok, vouchers} <- OwnershipVoucher.list(realm) do
      formatted_vouchers =
        Enum.map(vouchers, fn voucher ->
          OwnershipVoucherView.render("ownership_voucher.json", %{ownership_voucher: voucher})
        end)

      {:ok, formatted_vouchers}
    end
  end

  def register_ownership_voucher(_parent, args, %{context: %{realm_name: realm}}) do
    params = %{
      "ownership_voucher" => args.ownership_voucher,
      "key_name" => args.key_name,
      "key_algorithm" => args.key_algorithm,
      "replacement_public_key" => Map.get(args, :replacement_public_key),
      "replacement_guid" => Map.get(args, :replacement_guid),
      "replacement_rendezvous_info" => Map.get(args, :replacement_rendezvous_info)
    }

    params
    |> FDO.OwnershipVoucher.register(realm)
    |> handle_register_ownership_voucher()
  end

  defp handle_register_ownership_voucher({:ok, resp}) do
    {:ok,
     %{
       public_key: resp.public_key,
       guid: UUID.binary_to_string!(resp.guid)
     }}
  end

  defp handle_register_ownership_voucher({:error, %Ecto.Changeset{} = changeset}) do
    changeset_error(changeset)
  end

  defp handle_register_ownership_voucher({:error, reason}) do
    {:error, reason}
  end

  defp changeset_error(changeset) do
    {:error, "Validation failed: #{format_changeset_errors(changeset)}"}
  end

  defp format_changeset_errors(changeset) do
    changeset
    |> ChangesetView.translate_errors()
    |> Jason.encode!()
  end

  def delete_ownership_voucher(_parent, %{guid: guid}, %{context: %{realm_name: realm}}) do
    case delete_voucher(realm, guid) do
      :ok -> {:ok, guid}
      {:error, reason} -> {:error, "Failed to delete voucher: #{inspect(reason)}"}
    end
  end

  # Vouchers are stored by their binary GUID, while clients see its string form.
  defp delete_voucher(realm, guid) do
    with {:ok, binary_guid} <- dump_guid(guid) do
      OwnershipVoucher.delete(realm, binary_guid)
    end
  end

  defp dump_guid(guid) do
    case Ecto.UUID.dump(guid) do
      {:ok, _binary_guid} = ok -> ok
      :error -> {:error, :not_found}
    end
  end
end
