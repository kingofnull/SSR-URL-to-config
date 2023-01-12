function isProtecolSupported(protecol){
	//clash supported Protecols
	const suportedProtecols=['origin','auth_sha1_v4','auth_aes128_md5','auth_aes128_sha1','auth_chain_a','auth_chain_b' ];
	
	return (suportedProtecols.indexOf(protecol)>-1);
}

function isObfsSupported(obfs){
	//clash supported OBFSes
	const suportedObfses=['plain','http_simple','http_post','random_head','tls1.2_ticket_auth','tls1.2_ticket_fastauth'];
	
	return (suportedObfses.indexOf(obfs)>-1);
}

function isCypherSupported(cypher){
	//clash supported cyphers
	const suportedCyphers=["aes-128-cfb","aes-192-cfb","aes-256-cfb","aes-128-ctr","aes-192-ctr","aes-256-ctr","rc4-md5","chacha20-ietf","xchacha20"];
	
	return (suportedCyphers.indexOf(cypher)>-1);
}

function base64Decode(str){
	let r="";
	try{
		r=atob(str);
	}catch(e){
		consoleLog("Error: Fail to decode base64 string of `"+str+"` , Error: "+e.message);
	}
	
	
	return r;
}

function jsonDecode(str){
	return JSON.parse(str);
}

function jsonEncode(data){
	return JSON.stringify(data);
}

function parseUrlParams(url){
	const urlSearchParams = new URLSearchParams(url);
	const params = Object.fromEntries(urlSearchParams.entries());
	
	return params;
}

function consoleLog(text){
	document.querySelector("#console").value+=text+"\n";
	console.log(text);
}

function consoleClear(){
	document.querySelector("#console").value="";
	console.clear();
}

function parseURI2ClashData(uri,parseParams=false){

	let m=uri.match(/(?<type>(ssr?)|vmess):\/\/(?<data>[a-z\d\=\_\+\/]+)(@(?<server>[^:]+):(?<port>\d+))?(\#(?<remark>.+))?/i)
	
	if(!m){
		return null;
	}
	
	let data={};
	
	let s=m.groups;
	
	if(s['server']){
		data['server']=s['server'];
		data['port']=s['port'];
	}
	
	data['type']=s['type'].toLowerCase();
	
	//{"add":"arvancloud.com","aid":"0","host":"mahsaproxy.com","id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"ws","path":"/graphql","port":"80","ps":"@DARK_SHADOWSOCKS","scy":"auto","sni":"","tls":"","type":"","v":"2"}
	//  - {"type":"vmess","name":"@DARK_SHADOWSOCKS","ws-opts":{"path":"/graphql","headers":{"host":"mahsaproxy.com"}},"server":"arvancloud.com","port":"80","uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":"0","cipher":"auto","network":"ws"}

	
	if(s['type']=="vmess"){
		let vmessText=base64Decode(s['data']);
		
		let vmessData=jsonDecode(vmessText);
		if(vmessData.v==2){
			data=Object.assign(data,{
				"server":vmessData.add ,
				"port":vmessData.port ,
				"uuid":vmessData.id ,
				"alterId":vmessData.aid ,
				"cipher": vmessData.scy ? vmessData.scy : "auto" ,
				"network":  vmessData.net,
				
				"tls":  vmessData.tls=="tls",
			});
            
            
            if(data["network"]=="ws"){
                
                data["ws-opts"]={};
                if(vmessData.path){
                    data["ws-opts"]["path"]= vmessData.path ;
                }
                
                if(vmessData.host){
                    data["ws-opts"]["headers"]={
						"Host":vmessData.host ,
					};
                }
                
                if(!data["ws-opts"]){
                   delete data["ws-opts"];
                }
            }            
                        
            if(data["network"]=="h2"){
                
                data["h2-opts"]={};
                if(vmessData.path){
                    data["h2-opts"]["path"]= vmessData.path ;
                }
                
                if(vmessData.host){
                    data["h2-opts"]["host"]=vmessData.host.split();
                }
                
                if(!data["h2-opts"]){
                    delete data["h2-opts"];
                }
            }
              
            if(data["type"]=="http"){
                data["network"]="http"
                data["http-opts"]={};
                
                if(vmessData.path){
                    data["http-opts"]["path"]=vmessData.path.split();
                }
                
                if(vmessData.host){
                    data["http-opts"]["headers"]={
						"Host":vmessData.host,
					};
                }
                
                if(!data["http-opts"]){
                    delete data["http-opts"];
                }
             
            }
   
            if(data["network"]=="grpc"){
                data["grpc-opts"]={
					"grpc-service-name": vmessData.path ? vmessData.path : "",
                };
            }

            
		}
		
	} 
	
	
	if(data['type']=="ss"){
		let ssText=base64Decode(s['data']);
		//var_dump(ssText);
		let ssRegex=/^(?<cipher>[^:]+):(?<password>[^:@]+)@(?<server>[^:]+):(?<port>\d+)$/i;
		if(s['server']){
			ssRegex=/^(?<cipher>[^:]+):(?<password>[^:]+)$/i;
		}
		
		let mSS=ssText.match(ssRegex)
		if(mSS){
			//merging regex extracted to main data object
			data={...data,...mSS.groups};
			//var_dump(ssText,ssRegex,mSS,data);
			//echo ssText."\n";
		}

	} 
	
	
	if(data['type']=="ssr"){
		s['data']
		.split("_")
		.forEach(ssrText=>{
			ssrText=base64Decode(ssrText);
			//echo "ssrText\n";
			let mSSR=ssrText.match(/(?<server>[^:]+):(?<port>\d+):(?<protocol>[^:]+):(?<cipher>[^:]+):(?<obfs>[^:]+):(?<password>[^\/:]+)\/?/i);
			if(mSSR){
				if(mSSR.groups['password']){
					mSSR.groups['password']=base64Decode(mSSR.groups['password']);
				}
				//merging regex extracted to main data object
				data={...data,...mSSR.groups};
				
			}
			
			let mSSR2=ssrText.match(/(?<params>([a-z]+=[^=&\/:\s]*&?)+)/i);
			
			if(parseParams && mSSR2){
				//var_dump(mSSR2);
                try{
                    parsedParams=parseUrlParams(mSSR2.groups['params']);  
                }catch(e){
                    consoleLog(`Fail to parse SSR of ${uri}.\n {e.message} \n`);
                    console.error(e);
                }
				for (const k in parsedParams) {
				  parsedParams[k]=base64Decode(parsedParams[k]);
				}
				data={...data,...parsedParams};

			}
			if(!data["protocol"]){
				consoleLog(`Error: Fail to parse SSR of ${uri}.\n`);
				return null;
			}
		})
	}
	//var_dump(data);
	return data;
}

function clashVmess2Url(r){
      let data={
          add:r.server,
          port:r.port,
          id:r.uuid,
          aid:r.alterId,
          scy: r.cipher ? r.cipher : "auto",
          net:r.network,
          //path: r["http-opts"]["path"][0] ,
          tls: r.tls? "tls" : "",
          v:2,
      };
      if(r.network=="ws"){
          data.path= r["ws-opts"]?.path || "";
          data.host= r["ws-opts"]?.headers?.Host || "";
      }
      
      if(r.network=="h2"){
          data.path= r["h2-opts"]?.["path"] || "";
          data.host= r["h2-opts"]?.["host"]?.join(',') || "";
      }
    
      if(r.network=="http"){
          data.net="tcp";
          data.path= r["http-opts"]?.["path"] || "";
          data.host= r["http-opts"]?.headers?.Host  || "";
      }
    
      let url=`vmess://`+base64encode(JSON.stringify(data));
      // console.log(r.network ,url,'\n',data,'\n');
      //console.log(r.network ,url,'\n');
      return url;
}