defmodule TestJwt do
  def run do
    token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3OTMxMTY3NTYsImFfaGEiOlsiLio6Oi4qIl0sInN1YiI6Im15X2FkbWluX3VzZXIiLCJyb2xlcyI6WyJhZG1pbiJdfQ.BxoPX_A2wATAYjrdz0RnCgVdAc2qAbp0esEPh5Vz8yR_zAOVilUuTk1jfpK2k7Sh63tkRawYbuwQw7QpgRbcsA"
    
    {:ok, pem} = File.read("../compose/astarte-keys/housekeeping_public.pem")
    jwk = JOSE.JWK.from_pem(pem)
    
    Astarte.HousekeepingWeb.AuthGuardian.decode_and_verify(token, %{}, secret: jwk)
    |> IO.inspect()
  end
end

TestJwt.run()
