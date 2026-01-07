# Exclude platform-specific tests that don't match the current OS
excludes =
  case :os.type() do
    {:unix, :darwin} -> [:linux]
    {:unix, :linux} -> [:darwin]
    _ -> [:darwin, :linux]
  end

ExUnit.start(exclude: excludes)
