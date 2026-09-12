//! Diagnostic probe. Ignored by default.

use codegraph_extract::{Walker, lang};

fn show(ext: &str, path: &str, src: &str) {
    let cfg = lang::for_extension(ext).expect("config");
    let mut w = Walker::new(cfg).expect("walker");
    let f = w.extract(path, src.as_bytes()).expect("extract");
    println!("== {path}");
    for (i, name, rel) in &f.supertypes {
        println!("   {} -> {name} [{rel:?}]", f.symbols[*i as usize].name);
    }
}

#[test]
#[ignore]
fn show_supertypes() {
    show("py", "a.py", "from typing import Protocol
import abc

class P(Protocol):
    def run(self, x): ...

class Meta(type): pass

class C(Base, P, metaclass=Meta):
    def run(self, x):
        helper(1, 2)

class D(abc.ABC): pass

class E(Generic[T]): pass
");
    show("ts", "a.ts", "interface Greeter { greet(n: string): void }
interface Sub extends Greeter {}
class Base {}
class Impl extends Base implements Greeter, Other<T> {
  greet(n: string): void { helper(1, 2); }
}
");
}
