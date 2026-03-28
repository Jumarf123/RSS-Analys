mod app;

fn main() {
    // Delegate the full application flow to the modular app layer.
    app::entry_point();
}
