defmodule Astarte.RealmManagementWeb.GraphQL.Resolvers.ConfigResolver do
  alias Astarte.RealmManagement.RealmConfig

  def get_auth_config(_parent, _args, %{context: %{realm_name: realm_name}}) do
    case RealmConfig.get_auth_config(realm_name) do
      {:ok, config} -> {:ok, format_auth_config(config)}
      {:error, reason} -> {:error, format_error(reason)}
    end
  end

  def get_device_registration_limit(_parent, _args, %{context: %{realm_name: realm_name}}) do
    case RealmConfig.get_device_registration_limit(realm_name) do
      {:ok, limit} -> {:ok, limit}
      {:error, reason} -> {:error, format_error(reason)}
    end
  end

  def get_datastream_maximum_storage_retention(_parent, _args, %{context: %{realm_name: realm_name}}) do
    case RealmConfig.get_datastream_maximum_storage_retention(realm_name) do
      {:ok, retention} -> {:ok, retention}
      {:error, reason} -> {:error, format_error(reason)}
    end
  end

  def update_auth_config(_parent, %{data: data}, %{context: %{realm_name: realm_name}}) do
    # We expect `data` to be a generic JSON map here (using our JSON scalar)
    case RealmConfig.update_auth_config(realm_name, data) do
      :ok -> {:ok, "Auth config updated successfully"}
      {:error, reason} -> {:error, format_error(reason)}
    end
  end

  # Helper to transform internal AuthConfig struct into a map for GraphQL JSON scalar
  defp format_auth_config(%RealmConfig.AuthConfig{} = config) do
    config
    |> Map.from_struct()
    |> Map.drop([:__meta__])
  end

  defp format_error(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> inspect()
  end
  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(reason), do: inspect(reason)
end
