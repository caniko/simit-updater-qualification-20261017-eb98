{
  outputs = _: {
    simitConfig.ci = {
      platform = "github";
      provider = "actions";
      runtime = "cargo";
      runner = "ubuntu-24.04";
    };
  };
}
