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

function parseURI(uri,parseParams=false){

	let m=uri.match(/(?<type>(ssr?)|vmess):\/\/(?<data>[a-z\d\=\_]+)(@(?<server>[^:]+):(?<port>\d+))?(\#(?<remark>.+))?/i)
	
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
	
	if(s['type']=="vmess"){
		let vmessText=base64Decode(s['data']);
		
		let vmessData=jsonDecode(vmessText);
		
		data.push({
			"server":vmessData.add ,
			"servername":vmessData.host ,
			"port":vmessData.port ,
			"uuid":vmessData.id ,
			"alterId":vmessData.aid ,
			"cipher": "auto" ,
			"network":  vmessData.net,
			"ws-path":  vmessData.path,
			"tls":  vmessData.tls=="tls",
		});
	} 
	
	
	if(data['type']=="ss"){
		let ssText=base64Decode(s['data']);
		//var_dump(ssText);
		let ssRegex=/^(?<cipher>[^:]+):(?<password>[^:@]+)@(?<server>[^:]+):(?<port>\d+)$/i;
		if(s['server']){
			ssRegex=/^(?<cipher>[^:]+):(?<password>[^:@]+)$/i;
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
				parsedParams=parseUrlParams(mSSR2.groups['params']);
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

function extractSsAndSsr(text){

	let matchesIt=text.matchAll(/(?<URI>((ssr?)|vmess):\/\/[^<>\n\s]+)/ig);
	
	let proxyList=[];
	
	for(let m of matchesIt){
		let url=m.groups.URI;
		
		let data=parseURI(url,true);
		
		if(!data){
			continue;
		}
		
		if(data['type']=="ssr"){
			if(!data['protocol']){
				consoleLog("Warining: skip due to empty protecol of "+m[0]+"\n");
				continue;
			}
			
			
			if(!isProtecolSupported(data['protocol'])){
				consoleLog("Warining: skip due to unsupported protocol of "+data['protocol']);
				continue;
			}
			
			if(!isObfsSupported(data['obfs'])){
				consoleLog("skip due to unsupported obfs!");
				continue;
			}
			
			if(!isCypherSupported(data['cipher'])){
				consoleLog("Warining: skip due to unsupported cipher of "+data['cipher']);
				continue;
			}
		}
		
		proxyList.push(data);
	}
	
	return proxyList;
}

function serializeForClacsh(proxyList){
	let ymlClashDump="proxies:\n";
	
	for(let p of proxyList){
		try{
			let jsonStr=jsonEncode(p);
			ymlClashDump+="  - "+jsonStr+"\n";
		}catch(e){
			consoleLog(`skiping due to encode error: ${e.getMessage()}`);
			//throw $e;
		}
		
		
	}
	return ymlClashDump;
}

function doConvert(){
	consoleClear();
	let rawInput=document.querySelector("#input").value;
	let proxies=extractSsAndSsr(rawInput,true);
	if(proxies.length<1){
		consoleLog("Error: No entry found. Exiting...");
		return;
	}

	let clashYml=serializeForClacsh(proxies);
	document.querySelector("#output").value=clashYml;
}

if(!"".matchAll){
	alert("This tool not going to work on old browsers. \n Please try on latest version.");
}

