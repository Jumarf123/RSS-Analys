#[cfg(target_os = "windows")]
fn main() {
    let manifest = r#"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="RSS-Analys" type="win32"/>
  <description>RSS-Analys</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#;

    let mut res = winres::WindowsResource::new();
    res.set_icon("rss.ico");
    res.set_manifest(manifest);
    if let Err(e) = res.compile() {
        panic!("failed to compile Windows resources: {e}");
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {}
