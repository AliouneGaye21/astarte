#
# This file is part of Astarte.
#
# Copyright 2018 Ispirata Srl
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

defmodule Astarte.RealmManagementWeb.Plug.AuthorizePath do
  @moduledoc """
  A Plug to handle authentication.

  This plug checks the global configuration to determine if authentication is enabled and enforces authentication.
  """
  alias Astarte.RealmManagement.Config

  def init(opts) do
    opts
  end

  def call(conn, _opts) do
    if Config.authentication_disabled?() do
      conn
    else
      Astarte.RealmManagementWeb.Plug.AuthPipeline.call(conn, [])
    end
  end
end

defmodule Astarte.RealmManagementWeb.Plug.AuthPipeline do
  @moduledoc false
  use Plug.Builder

  alias Astarte.RealmManagementWeb.AuthGuardian
  alias Astarte.RealmManagementWeb.FallbackController

  plug Guardian.Plug.Pipeline,
    otp_app: :astarte_realm_management,
    module: AuthGuardian,
    error_handler: FallbackController

  plug Astarte.RealmManagementWeb.Plug.VerifyHeader
  plug Guardian.Plug.EnsureAuthenticated
  plug Guardian.Plug.LoadResource
end
