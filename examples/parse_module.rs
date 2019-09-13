use bpf::Module;

fn main() {
    for arg in std::env::args().skip(1) {
        eprintln!("loading {}", arg);
        let code = std::fs::read(arg).unwrap();
        let m = Module::parse(&code).unwrap();
        eprintln!("{:?}", m);
    }
}
