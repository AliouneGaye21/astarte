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

defmodule Astarte.PairingWeb.GraphQL.Resolvers.Introspection do
  @moduledoc """
  Translates the initial introspection GraphQL arguments into the shape the
  REST API takes.
  """

  @doc """
  GraphQL has no maps with arbitrary keys, so the introspection comes in as a
  list of entries, already checked by Absinthe against
  `:introspection_entry_input`; device registration takes the REST API's map
  shape.
  """
  def to_map(nil), do: %{}

  def to_map(entries) do
    Map.new(entries, fn %{interface: interface, major_version: major, minor_version: minor} ->
      {interface, %{"major" => major, "minor" => minor}}
    end)
  end
end
