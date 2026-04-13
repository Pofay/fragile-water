defmodule FragileWater.Core.Handlers do
  @cmd_auth_logon_challenge 0
  @cmd_auth_logon_proof 1
  @cmd_realm_list 16

  @auth_handlers %{
    @cmd_auth_logon_challenge => FragileWater.Core.Cmd.AuthLogonChallenge,
    @cmd_auth_logon_proof => FragileWater.Core.Cmd.AuthLogonProof,
    @cmd_realm_list => FragileWater.Core.Cmd.RealmList
  }

  def get_auth_handler(opcode) do
    Map.get(@auth_handlers, opcode)
  end
end
