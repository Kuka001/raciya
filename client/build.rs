fn main() {
    let cfg = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/app.slint", cfg).expect("slint build");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        // FileDescription — имя, под которым программа видна в Диспетчере задач.
        res.set("ProductName", "Рация");
        res.set("FileDescription", "Рация");
        res.set("CompanyName", "Raciya");
        res.set("LegalCopyright", "");
        res.set_language(0x0419);
        res.compile().expect("resource build");
    }
}
