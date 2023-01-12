

function extractSsAndSsr(text){

	let matchesIt=text.matchAll(/(?<URI>((ssr?)|vmess):\/\/[^<>\n\s]+)/ig);
	
	let proxyList=[];
	
	for(let m of matchesIt){
		let uri=m.groups.URI;
        let data;
		try{
            data=parseURI2ClashData(uri,true);
        }catch(e){
            consoleLog(`Error: Fail to parse URI of ${uri}.\n [${e.message}] \n`);
            console.error(e);
        }
		
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
		
		data.name=data['type']+"_"+proxyList.length;
		if(proxyList.findIndex(v2=>(v2.server===data.server))==-1){
			proxyList.push(data);
		}
	}
	
	return proxyList;
}

function extractTls(text){

	let matchesIt=text.matchAll(/HTTPS\s+(?<server>[\w\.\-]+)\:(?<port>\d+)/ig);
	
	let proxyList=[];
	
	for(let m of matchesIt){
		
		let data=m.groups;
		
		if(!data){
			continue;
		}
		
		data.name="TLS_"+proxyList.length;
		data.type="http";
		data.tls=true;
		if(proxyList.findIndex(v2=>(v2.server===data.server))==-1){
			proxyList.push(data);
		}
		
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
	
	ymlClashDump+="\nproxies-names:\n";
	for(let p of proxyList){
		try{
			ymlClashDump+="  - "+p.name+"\n";
		}catch(e){
			consoleLog(`skiping due to encode error: ${e.getMessage()}`);
			//throw $e;
		}
		
		
	}
	
	return ymlClashDump;
}

function doConvert(mode){
	consoleClear();
	let rawInput=document.querySelector("#input").value;
    let convertResult="";
    if(mode=="uri2clash"){
        let proxies=extractSsAndSsr(rawInput,true);
        proxies=proxies.concat(extractTls(rawInput));
        if(proxies.length<1){
            consoleLog("Error: No entry found. Exiting...");
            return;
        }

        convertResult=serializeForClacsh(proxies);
    }

	document.querySelector("#output").value=convertResult;
}

if(!"".matchAll){
	alert("This tool not going to work on old browsers. \n Please try on latest version.");
}

