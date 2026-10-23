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

defmodule Astarte.Auth.ConfigTest do
  use ExUnit.Case, async: true
  use Mimic

  alias Astarte.Auth.Config
  alias Astarte.Auth.OpenFGA

  describe "store_id!/2" do
    test "keeps a configured store id without looking the store up" do
      reject(&OpenFGA.fetch_store_id/1)

      assert Config.store_id!("01STOREID", "astarte") == "01STOREID"
      assert Config.store_id!("01STOREID", nil) == "01STOREID"
    end

    test "looks the store id up by name when no id is configured" do
      for unset <- [nil, ""] do
        expect(OpenFGA, :fetch_store_id, fn "astarte" -> {:ok, "01FOUND"} end)

        assert Config.store_id!(unset, "astarte") == "01FOUND"
      end
    end

    test "raises when neither a store id nor a store name is configured" do
      reject(&OpenFGA.fetch_store_id/1)

      for id <- [nil, ""], name <- [nil, ""] do
        assert_raise RuntimeError,
                     ~r/ASTARTE_OPENFGA_STORE_ID or ASTARTE_OPENFGA_STORE_NAME/,
                     fn ->
                       Config.store_id!(id, name)
                     end
      end
    end

    test "raises when the named store can't be found" do
      for reason <- [:not_found, :ambiguous, :econnrefused] do
        expect(OpenFGA, :fetch_store_id, fn "astarte" -> {:error, reason} end)

        assert_raise RuntimeError, ~r/Couldn't find the OpenFGA store named "astarte"/, fn ->
          Config.store_id!(nil, "astarte")
        end
      end
    end
  end
end
