use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use chrono::NaiveDateTime;

// 定义双keyIp结构
#[derive(Debug, Clone)]
struct AdKey {
    address: String,
}

// 为AdKey实现Hash trait
impl Hash for AdKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}
impl PartialEq for AdKey {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}
impl Eq for AdKey {}

// 定义记录值结构
#[derive(Debug, Clone)]
pub struct AdValue {
    pub name: String,
    pub domain: String,
    pub time_string: String,
    pub time_stamp: NaiveDateTime
}

// 定义AdRecord管理结构
pub struct AdRecordMap {
    ip_records: HashMap<AdKey, AdValue>,
}

impl AdRecordMap {
    // 创建新实例
    pub fn new() -> Self {
        AdRecordMap { ip_records: HashMap::new() }
    }

    // 更新记录，如果记录不存在则插入新记录
    pub fn update(&mut self, name: &String, domain: &String, address: &String, time: &String) -> Option<(bool, AdValue)> {
        let time_stamp= NaiveDateTime::parse_from_str(time.clone().as_str(), "%Y-%m-%d %H:%M:%S%.9f UTC").unwrap();
        let new_key = AdKey { address: address.clone() };
        let new_value = AdValue { name: name.clone(), domain: domain.clone(), time_string: time.clone(),  time_stamp:  time_stamp };

        let current_value = self.ip_records.get_mut(&new_key);
        if current_value.is_none() {
            let ret = new_value.clone();
            self.ip_records.insert(new_key, new_value);
            return Some((false, ret));
        }

        let current_value_record = current_value.unwrap();
        if current_value_record.domain != new_value.domain || current_value_record.name != new_value.name {
            let old_value = current_value_record.clone();
            // 说明域名变了
            current_value_record.name = new_value.name.clone();
            current_value_record.domain = new_value.domain.clone();

            current_value_record.time_string = new_value.time_string.clone();
            current_value_record.time_stamp = new_value.time_stamp;
            return Some((true, old_value));
        }

        if current_value_record.time_stamp < new_value.time_stamp {
            current_value_record.time_string = new_value.time_string.clone();
            current_value_record.time_stamp = new_value.time_stamp;
        }

        return None;
    }
}