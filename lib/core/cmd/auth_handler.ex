defmodule FragileWater.Core.Cmd.AuthHandler do
  @callback generate_payload(request :: binary, state :: map) ::
              {:continue, new_state :: map, response :: binary}
              | {:close, new_state :: map}

  @callback post_handle(state :: map) :: new_state :: map
end
