use eframe::egui;
use std::sync::Arc;
use std::sync::Mutex;
use log::{info, warn};
use tokio::runtime::Runtime;
use crate::account::Account;
use crate::file::{init_load, init_load_user, SessionKey};
use crate::message::Message;
use crate::session::Session;
use crate::socket::{get_session, search};


#[derive(Clone)]
pub struct AppState {
    input_text: String,
    current_page: Page,
    account: Arc<Mutex<Option<Account>>>,
    target: Arc<Mutex<Option<Session>>>,
    backup_user: Vec<String>,
    pub search_results: Arc<Mutex<Vec<String>>>,
    load_user: Vec<String>,
    runtime: Arc<Runtime>,
}

impl AppState {
    fn send_message(&mut self) {
        if !self.input_text.trim().is_empty() {
            self.target.lock().unwrap().as_ref().unwrap().add_message(Message::new(self.input_text.clone()));
            self.input_text.clear();
        }
    }
    
    pub fn new() -> Self {
        Self {
            input_text: String::new(),
            current_page: Page::Login,
            account: Arc::new(Mutex::new(None)),
            target: Arc::new(Mutex::new(None)),
            backup_user: init_load(),
            search_results: Arc::new(Mutex::new(vec![])),
            load_user: Vec::new(),
            runtime: Arc::new(Runtime::new().unwrap()),
        }
    }

    fn show_login_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Login Page");
        
        ui.horizontal(|ui| {
            ui.label("Account:");
            ui.text_edit_singleline(&mut self.input_text);
        });

        if ui.button("Login").clicked() {
            if self.backup_user.contains(&self.input_text) {
                match Account::load(self.input_text.to_string()) { 
                    Ok(account) => {
                        info!("Loaded account {:?}", account.name());
                        self.account.lock().unwrap().replace(account);
                        self.current_page = Page::Search;
                        self.input_text.clear();
                        self.search_results.lock().unwrap().clear();
                        self.load_user = init_load_user(&self.input_text);
                    },
                    Err(e) => {
                        ui.label("Error loading account");
                        info!("Error loading account: {:?}", e);
                    }
                }    
            } else {
                let account_clone = Arc::clone(&self.account);
                let string_clone = self.input_text.clone();
                
                self.runtime.spawn(async move {
                    match Account::new(string_clone).await {
                        Ok(account) => {
                            info!("Created account {:?}", account.name());
                            *account_clone.lock().unwrap() = Some(account);
                        },
                        Err(e) => {
                            info!("Error creating account: {:?}", e);
                        }
                    }
                });
                
                self.current_page = Page::Search;
                self.input_text.clear();
                self.search_results.lock().unwrap().clear();
            }
        }

        ui.add_space(10.0);
        ui.label("Recent Login Users:");

        for result in &self.backup_user {
            if ui.button(result).clicked() {
                match Account::load(result.to_string()) { 
                    Ok(account) => {
                        info!("Loaded account {:?}", account.name());
                        self.account.lock().unwrap().replace(account);
                        self.current_page = Page::Search;
                        self.input_text.clear();
                        self.search_results.lock().unwrap().clear();
                        self.load_user = init_load_user(result);
                    },
                    Err(e) => {
                        ui.label("Error loading account");
                        info!("Error loading account: {:?}", e);
                    }
                }
            }
        }
    }

    fn show_search_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Back").clicked() {
                self.current_page = Page::Login;
                self.backup_user = init_load();
                self.account.lock().unwrap().take();
                self.input_text.clear();
            }
            ui.heading("Search User");
        });

        ui.add_space(10.0);
        ui.label(format!("Current User: {}", if let Some(account) = &*self.account.lock().unwrap() {
            account.name()
        } else { 
            "None"
        }));
        
        ui.horizontal(|ui| {
            ui.label("Search:");
            ui.text_edit_singleline(&mut self.input_text);
        });

        if ui.button("Search").clicked() {
            let search_results = Arc::clone(&self.search_results);
            let input_text = self.input_text.clone();
            let account = self.account.lock().unwrap().as_ref().unwrap().name().to_string();
            
            self.runtime.spawn(async move {
                match search(&account, &input_text).await {
                    Ok(results) => {
                        info!("Search results: {:?}", results);
                        *search_results.lock().unwrap() = results;
                    },
                    Err(e) => {
                        info!("Error searching: {:?}", e);
                    }
                }    
            });
            
            self.input_text.clear();
        }

        for result in self.search_results.lock().unwrap().iter() {
            if ui.button(result).clicked() {
                if self.load_user.contains(result) {
                    match SessionKey::load(result, self.account.clone()) {
                        Ok(session) => {
                            info!("Loaded session {:?}", session.name());
                            self.target.lock().unwrap().replace(session);
                            self.current_page = Page::Chat;
                            self.input_text.clear();
                        },
                        Err(e) => {
                            ui.label("Error loading session");
                            warn!("Error loading session: {:?}", e);
                        }
                    }
                } else {
                    let input_text = result.clone();
                    let target = Arc::clone(&self.target);
                    let account = self.account.clone();

                    self.runtime.spawn(async move {
                        match get_session(&input_text, account).await {
                            Ok(session) => {
                                info!("Got session for {input_text}");
                                *target.lock().unwrap() = Some(session);
                            },
                            Err(e) => {
                                warn!("Error getting session: {:?}", e);
                            }
                        }
                    });
                    self.current_page = Page::Chat;
                    self.input_text.clear();
                }
            }
        }
        
        ui.label("Session:");
        
        for result in &self.load_user {
            if ui.button(result).clicked() {
                match SessionKey::load(result, self.account.clone()) {
                    Ok(session) => {
                        info!("Loaded session {:?}", session.name());
                        self.target.lock().unwrap().replace(session);
                        self.current_page = Page::Chat;
                        self.input_text.clear();
                    },
                    Err(e) => {
                        ui.label("Error loading session");
                        info!("Error loading session: {:?}", e);
                    }
                }
            }
        }
    }

    fn show_chat_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Back").clicked() {
                self.current_page = Page::Search;
                self.search_results.lock().unwrap().clear();
                self.target.lock().unwrap().take();
                self.input_text.clear();
                self.load_user = init_load_user(&self.account.lock().unwrap().as_ref().unwrap().name());
            }
            ui.heading(format!("Chat with {}", self.target.lock().unwrap().as_ref()
                .map_or("Default Name", |target| target.name())
            ));
        });
        
        egui::ScrollArea::vertical().show(ui, |ui| {
            match self.target.lock().unwrap().as_ref() { 
                Some(messages) => {
                    for msg in messages.message().lock().unwrap().iter() {
                        if msg.sender {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                                ui.label(format!("{} - {}", msg, msg.timestamp()));
                            });
                        } else {
                            ui.with_layout(egui::Layout::left_to_right(egui::Align::TOP), |ui| {
                                ui.label(format!("{} - {}", msg, msg.timestamp()));
                            });
                        }
                    }
                },
                None => {
                    ui.label("No messages");
                }
            }
            
        });

        ui.separator();

        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.input_text);
            if ui.button("Send").clicked() {
                self.send_message();
                self.input_text.clear();
            }
        });
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_page {
                Page::Login => self.show_login_page(ui),
                Page::Search => self.show_search_page(ui),
                Page::Chat => self.show_chat_page(ui),
            }
        });
        ctx.request_repaint();
    }
}

#[derive(Clone)]
enum Page {
    Login,
    Search,
    Chat,
}