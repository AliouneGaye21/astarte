defmodule Astarte.RealmManagementWeb.GraphQL.Resolvers.DeviceResolver do
  alias Astarte.RealmManagement.Devices

  def delete_device(_parent, %{device_id: device_id}, %{context: %{realm_name: realm_name}}) do
    case Devices.delete_device(realm_name, device_id) do
      :ok -> {:ok, "Device deletion initiated"}
      {:error, reason} -> {:error, format_error(reason)}
    end
  end

  defp format_error(reason), do: inspect(reason)
end
