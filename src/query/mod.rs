use tokio::sync::mpsc;
use windows::Win32::System::EventLog::*;
use std::error::Error;
use std::sync::Mutex;
use std::sync::LazyLock;
use windows::core::PCWSTR;

static SENDER: LazyLock<Mutex<Option<mpsc::Sender<String>>>> = LazyLock::new(|| Mutex::new(None));

const QUERY_STRING: PCWSTR = windows::core::w!(
    "Event/System[EventID=4624] and \
    Event/EventData/Data[@Name='LogonType']='3' and \
    (Event/EventData/Data[@Name='AuthenticationPackageName']='Kerberos' or Event/EventData/Data[@Name='AuthenticationPackageName']='NTLM') and \
    Event/EventData/Data[@Name='TargetUserSid']!='S-1-5-18' and \
    Event/EventData/Data[@Name='IpAddress']!='-' and \
    Event/EventData/Data[@Name='IpAddress']!='127.0.0.1' and \
    Event/EventData/Data[@Name='IpAddress']!='::' and \
    Event/EventData/Data[@Name='IpAddress']!='::1'");

// 解析事件 XML 数据
unsafe fn parse_event(event: EVT_HANDLE) -> Option<String> {
    let mut buffer = [0u16; 8192];
    let mut buffer_used = 0;
    let mut property_count = 0;

    unsafe {
        if EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            buffer.len() as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut buffer_used,
            &mut property_count,
        )
        .as_bool()
        {
            let event_xml = String::from_utf16_lossy(&buffer[..buffer_used as usize / 2]);
            Some(event_xml)
        } else {
            None
        }
    }
}

// 打开事件日志并读取内容
pub fn get_event() -> Result<Vec<String>, Box<dyn Error>> {
    unsafe {
        let mut events = Vec::new();

        // 创建查询
        let query = PCWSTR::from_raw(QUERY_STRING.as_ptr());
        let log_name = windows::core::PCWSTR::from_raw(windows::core::w!("Security").as_ptr());
        let query_handle = EvtQuery(None, log_name, query, EvtQueryTolerateQueryErrors.0)?;
        
        let mut event_handles: [isize; 10] = [0; 10];
        let mut events_read: u32 = 0;
        loop {
            let success = EvtNext(query_handle, &mut event_handles, 1500, 0, &mut events_read,);
           
            if !success.as_bool() { break; }
            
            let count = events_read as usize;
            for i in 0..count {
                let handle = event_handles[i];
                if let Some(event_xml) = parse_event(EVT_HANDLE(handle)) {
                    events.push(event_xml);
                }
                EvtClose(EVT_HANDLE(handle)); // 关闭事件句柄，防止内存泄漏
            }
            events_read += 1;
        }

        // 清理资源
        EvtClose(query_handle);
        Ok(events)
    }
}

// 订阅 Windows 事件日志
pub async fn subscribe_event(tx: mpsc::Sender<String>) -> Result<(), Box<dyn Error>> {
    unsafe {
        *SENDER.lock().unwrap() = Some(tx);

        extern "system" fn callback(
            _action: EVT_SUBSCRIBE_NOTIFY_ACTION,
            _user_context: *const std::ffi::c_void,
            event: EVT_HANDLE,
        ) -> u32 {
            if event.0 != 0 {
                match unsafe { parse_event(event) } {
                    None => {}
                    Some(event_data) => {
                        if let Some(sender) = SENDER.lock().unwrap().as_ref() {
                            let _ = sender.blocking_send(event_data);
                        }
                    }
                }
            }
            0
        }

        // 订阅日志 (只监听 Event ID 4624 - 成功登录)
         let query = PCWSTR::from_raw(QUERY_STRING.as_ptr());
        match EvtSubscribe(
            None,
            None,
            windows::core::PCWSTR::from_raw(windows::core::w!("Security").as_ptr()),
            query,
            EVT_HANDLE(0),
            None,
            Some(callback),
            EvtSubscribeToFutureEvents.0,
        ) {
            Ok(handle) => handle,
            Err(e) => { return Err(Box::new(e)); }
        };

        // 让主线程保持运行，避免订阅终止
        loop { std::thread::sleep(std::time::Duration::from_secs(1)); }
    }
}