mod query;
mod record;

use tokio;
use tokio::sync::mpsc;
use crate::query::get_event;
use crate::query::subscribe_event;
use crate::record::AdRecordMap;

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use quick_xml::Reader;
use quick_xml::events::Event;

// 定义一个函数来解析事件数据
fn parse_event_data(event_xml: &str) -> HashMap<String, String> {
    let mut reader = Reader::from_str(event_xml);
    reader.trim_text(true);
    
    let mut data = HashMap::new();
    let mut buf = Vec::new();
    let mut current_name = String::new();
    
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if e.name().local_name().as_ref() == b"Data" {
                    if let Some(name_attr) = e.attributes()
                        .find(|a| a.as_ref().ok()
                            .map(|attr| attr.key.as_ref() == b"Name")
                            .unwrap_or(false))
                    {
                        if let Ok(name) = std::str::from_utf8(&name_attr.unwrap().value) {
                            current_name = name.to_string();
                        }
                    }
                }
            },
            Ok(Event::Text(e)) => {
                if !current_name.is_empty() {
                    if let Ok(text) = std::str::from_utf8(e.as_ref()) {
                        data.insert(current_name.clone(), text.to_string());
                    }
                    current_name.clear();
                }
            },
            Ok(Event::Empty(e)) => {
                if e.name().local_name().as_ref() == b"TimeCreated" {
                    if let Some(time_attr) = e.attributes()
                        .find(|a| a.as_ref().ok()
                            .map(|attr| attr.key.as_ref() == b"SystemTime")
                            .unwrap_or(false))
                    {
                        if let Ok(time_str) = time_attr.unwrap().decode_and_unescape_value(&reader) {
                            if let Ok(datetime) = DateTime::parse_from_rfc3339(&time_str) {
                                let utc_time = datetime.with_timezone(&Utc);
                                data.insert("TimeCreated".to_string(), utc_time.to_string());
                            }
                        }
                    }
                }
            },
            Ok(Event::Eof) => break,
            _ => (),
        }
    }
    data
}

fn get_event_data(event: &str, record: &mut AdRecordMap) {
    let unknown = String::from("未知");
    let parsed_data = parse_event_data(event);

    let name = parsed_data.get("TargetUserName").unwrap_or(&unknown);
    // 跳过以 $ 结尾的系统账户
    if name.ends_with('$') {
        return;
    }
    let domain = parsed_data.get("TargetDomainName").unwrap_or(&unknown);
    let address = parsed_data.get("IpAddress").unwrap_or(&unknown);
    let time = parsed_data.get("TimeCreated").unwrap_or(&unknown);

    println!("update-{}-{}-{}-{}", name, domain, address, time);
    let update = record.update(&name, &domain, &address, &time);
    if update.is_none() {
        return ;
    }
    let (is_update, value) = update.unwrap();
    if is_update {
        println!("删除记录:");
        println!("\t用户名:\t{}", value.name);
        println!("\t域名:\t{}", value.domain);
        println!("\tIP地址:\t{}", address);
        println!("\t时间:\t{}", value.time_string);
    }

    println!("添加记录:");
    println!("\t用户名:\t{}", name);
    println!("\t域名:\t{}", domain);
    println!("\tIP地址:\t{}", address);
    println!("\t时间:\t{}", time);

}

#[tokio::main]
async fn main() {
    let mut record= AdRecordMap::new();
    let (tx, mut rx) = mpsc::channel::<String>(10);

    // 获取之前产生的event
    let events = get_event();
    match events {
        Ok(events) => {
            for event in events {
                get_event_data(&event, &mut record);
            }
        }
        Err(e) => {
            eprintln!("获取事件失败: {}", e);
        }
    }

    // 运行事件监听器
    tokio::spawn(async move {
        if let Err(e) = subscribe_event(tx).await {
            eprintln!("事件监听失败: {}", e);
        }
    });
    println!("开始监听事件");

    // 异步接收日志事件
    while let Some(event) = rx.recv().await {
        get_event_data(&event, &mut record);
    }
}