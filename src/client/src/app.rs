use eframe::egui;
use std::sync::Arc;
use std::sync::Mutex;
use log::{info, warn};
use tokio::runtime::Runtime;
use crate::account::Account;
use crate::file::{init_load, init_load_user, SessionKey};
use crate::message::Message;
use crate::session::Session;
use crate::socket::{get_session, get_session_list, search, MessagePayload, RequestPayload};


pub struct AppState {
    input_text: String,
    current_page: Page,
    account: Arc<Mutex<Option<Account>>>,
    target: Arc<Mutex<Option<Session>>>,
    message: Arc<Mutex<Vec<Message>>>,
    backup_user: Vec<String>,
    pub search_results: Arc<Mutex<Vec<String>>>,
    load_user: Vec<String>,
    request_user: Arc<Mutex<Vec<String>>>,
    runtime: Arc<Runtime>,
    refresh_task: Option<tokio::task::JoinHandle<()>>,
}

impl AppState {
    fn send_message(&mut self) {
        if !self.input_text.trim().is_empty() {
            let input_text = self.input_text.clone();
            let message = Message::new(input_text.to_string());
            let time = message.timestamp;
            self.message.lock().unwrap().push(message.clone());
            
            let payload = self.target.lock().unwrap().as_mut().unwrap().add_message(message);
            
            if let Ok(payload) = payload { 
                let account = {
                    self.account.lock().unwrap().as_ref().unwrap().name().to_string()
                };
                
                let target = {
                    self.target.lock().unwrap().as_ref().unwrap().name().to_string()
                };
                
                self.runtime.spawn(async move {
                    match MessagePayload::send(&account, &target, payload, time).await {
                        Ok(_) => { info!("Sent message"); },
                        Err(e) => { warn!("Error sending message: {:?}", e); }
                    }
                });
            } else {
                warn!("Error adding message");
            }
        }
    }
    
    pub fn new() -> Self {
        Self {
            input_text: String::new(),
            current_page: Page::Login,
            account: Arc::new(Mutex::new(None)),
            target: Arc::new(Mutex::new(None)),
            backup_user: init_load(),
            message: Arc::new(Mutex::new(vec![])),
            search_results: Arc::new(Mutex::new(vec![])),
            load_user: Vec::new(),
            request_user: Arc::new(Mutex::new(Vec::new())),
            runtime: Arc::new(Runtime::new().unwrap()),
            refresh_task: None,
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
                        let request_user = Arc::clone(&self.request_user);
                        let temp = self.input_text.clone();
                        
                        self.runtime.spawn(async move {
                            match get_session_list(&temp).await {
                                Ok(users) => {
                                    *request_user.lock().unwrap() = users;
                                },
                                Err(e) => {
                                    warn!("Error getting session list: {:?}", e);
                                }
                            }
                        });
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
                        let request_user = Arc::clone(&self.request_user);
                        let temp = result.clone();
                        
                        self.runtime.spawn(async move {
                            match get_session_list(&temp).await {
                                Ok(users) => {
                                    *request_user.lock().unwrap() = users;
                                },
                                Err(e) => {
                                    warn!("Error getting session list: {:?}", e);
                                }
                            }
                        });
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
                if self.request_user.lock().unwrap().contains(result) {
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
                } else if self.load_user.contains(result) {
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
        
        ui.label("Request:");
        for result in &*self.request_user.lock().unwrap() {
            if ui.button(result).clicked() {
                let result = result.clone();
                let account = self.account.clone();
                let target = Arc::clone(&self.target);
                self.runtime.spawn(async move {
                    match RequestPayload::receive(result, account).await {
                        Ok(session) => {
                            target.lock().unwrap().replace(session);
                        },
                        Err(e) => {
                            warn!("Error receiving request: {:?}", e);
                        }
                    }
                });
                self.current_page = Page::Chat;
                self.input_text.clear();
            }
        }
    }

    fn show_chat_page(&mut self, ui: &mut egui::Ui) {
        if self.refresh_task.is_none() {
            let target = Arc::clone(&self.target);
            let runtime = self.runtime.clone();
            let account = {
                match self.account.lock().unwrap().as_ref() { 
                    Some(account) => Some(account.name().to_string()),
                    None => None,
                }
            };
            
            let target_name = {
                match self.target.lock().unwrap().as_ref() {
                    Some(target) => Some(target.name().to_string()),
                    None => None,
                }
            };
            
            if let (Some(account), Some(target_name)) = (account, target_name) {
                let message = Arc::clone(&self.message);
                self.refresh_task = Some(runtime.spawn(async move {
                    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
                    loop {
                        interval.tick().await;
                        
                        match MessagePayload::receive(account.to_string(), target_name.to_string()).await {
                            Ok(messages) => {
                                let mut temp = vec![];
                                for message in messages {
                                    if let Some(target) = target.lock().unwrap().as_mut() {
                                        match target.revive_message(message.message, message.timestamp) {
                                            Ok(result) => {
                                                temp.push(result);
                                            },
                                            Err(e) => {
                                                warn!("Error reviving message: {:?}", e);
                                            }
                                        }
                                    }
                                }
                                message.lock().unwrap().extend(temp);
                            },
                            Err(e) => {
                                warn!("Error refreshing messages: {:?}", e);
                            }
                        }
                    }
                }));
            }
        }
        
        ui.horizontal(|ui| {
            if ui.button("Back").clicked() {
                self.current_page = Page::Search;
                self.search_results.lock().unwrap().clear();
                self.target.lock().unwrap().take();
                self.input_text.clear();
                self.load_user = init_load_user(&self.account.lock().unwrap().as_ref().unwrap().name());
                
                let temp = self.account.lock().unwrap().as_ref().unwrap().name().to_string();
                let request_user = Arc::clone(&self.request_user);
                self.runtime.spawn(async move {
                    match get_session_list(&temp).await {
                        Ok(users) => {
                            *request_user.lock().unwrap() = users;
                        },
                        Err(e) => {
                            warn!("Error getting session list: {:?}", e);
                        }
                    }
                });
            }
            ui.heading(format!("Chat with {}", self.target.lock().unwrap().as_ref()
                .map_or("Default Name", |target| target.name())
            ));
        });
        
        egui::ScrollArea::vertical().show(ui, |ui| {
            let messages = self.message.lock().unwrap();
            for msg in messages.iter() {
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