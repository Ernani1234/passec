// Sem console no build de release: uma janela de terminal atras do app
// vazaria qualquer coisa impressa por engano.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    passec_lib::run()
}
