import sys
from datetime import datetime
import requests
from requests.exceptions import RequestException
from urllib.parse import quote, urlparse 
from bs4 import BeautifulSoup
import re
import json
import os
import subprocess 


def check_injection(url):
    vuls = []

    payloads = [
    "' OR '1'='1",
    "\" OR 1=1--",
    "' OR 1=1#",
    "') OR ('1'='1"
    ]

    erros_sql = [
    "syntax error",
    "SQLSTATE",
    "mysql",
    "ORA-",
    "error in your SQL syntax"
    ]


    try:
        baseline = requests.get(url, timeout=5)
    except RequestException:
        return []
    
    for payload in payloads:
        test_url = f"{url}?test={payload}"

        try:
            resp = requests.get(test_url, timeout=5)
        except RequestException:
            continue

        texto = resp.text.lower()

        for erro in erros_sql:
            if erro in texto:
                vuls.append({
                    "tipo": "injection",
                    "severidade": "alta",
                    "url": test_url,
                    "detalhe": f"Possível SQL Injection detectada com payload: {payload}"
                  })
                
    return vuls







def check_xss(url):

    vuls = []

    payloads = [
    "<script>alert(1)</script>",
    "\"'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
    ]

    for payload in payloads:
        encoded_payload = quote(payload)
        test_url = f"{url}?xss={encoded_payload}"

        try:
           resp = requests.get(test_url, timeout=5)
        except RequestException:
            continue  
        corpo = resp.text
        if payload in corpo:
            vuls.append({
            "tipo": "xss",
            "severidade": "alta",
            "url": test_url,
            "detalhe": f"Possível XSS refletido com payload: {payload}"
            })

    return vuls


def check_csrf(url):

    vuls = []

    try:
        resp = requests.get(url, timeout=5)
    except RequestException:
        return []
    html = resp.text

    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")

    for form in forms:
        method = (form.get("method") or "").lower()
        if method != "post":
           continue  # só nos interessam formulários POST

        inputs = form.find_all("input")
        has_token = False

        for inp in inputs:
           name = (inp.get("name") or "").lower()
           input_type = (inp.get("type") or "").lower()

           if "csrf" in name or ("token" in name and input_type == "hidden"):
              has_token = True
              break
           
        if not has_token:
            action = form.get("action") or url
            vuls.append({
                "tipo": "csrf",
                "severidade": "media",
                "url": action,
                "detalhe": "Formulário POST sem token CSRF aparente"
            })
               
    return vuls


def check_directory_tranversal(url):

    vuls = []

    payloads = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\windows\\win.ini"
    ]

    indicadores = [
    "root:x:",        # /etc/passwd
    "[extensions]",   # win.ini
    "[files]",
     ]
    
    for payload in payloads:
        encoded_payload = quote(payload)
        test_url = f"{url}?file={encoded_payload}"

        try:
            resp = requests.get(test_url, timeout=5)
        except RequestException:
            continue  


        body = resp.text.lower()

        for indicador in indicadores:
            if indicador.lower() in body:
                vuls.append({
                    "tipo": "directory_traversal",
                    "severidade": "alta",
                    "url": test_url,
                    "detalhe": f"Possível Directory Traversal permitindo acesso a arquivos sensíveis com payload: {payload}"
                })

                break

    return vuls
        


def check_file_inclusion(url):
   vuls = []

   param_names = ["file", "page", "include", "inc", "template"]


   payloads = [
    "nonexistent.php",
    "http://example.com/",
    "php://filter/convert.base64-encode/resource=index.php"
   ]

   indicadores = [
    "include(): Failed opening",
    "require_once(): Failed opening",
    "include(): Failed opening required",
    "failed to open stream: No such file or directory in",
    "Failed opening required"
   ]

   for param in param_names:
       for payload in payloads:
           encoded_payload = quote(payload)

           if "?" in url:
                test_url = f"{url}&{param}={encoded_payload}"
           else:
                test_url = f"{url}?{param}={encoded_payload}"

           try:
                resp = requests.get(test_url, timeout=5)
           except RequestException:
                continue
           
           body = resp.text.lower()

           suspeito = False
           for indicador in indicadores:
                if indicador.lower() in body:
                    suspeito = True
                    break
           if not suspeito and payload.startswith("http://example.com"):
                if "example domain" in body:
                    suspeito = True

           if suspeito:
                vuls.append({
                    "tipo": "file_inclusion",
                    "severidade": "alta",
                    "url": test_url,
                    "detalhe": f"Possível File Inclusion detectada usando parâmetro '{param}' com payload: {payload}"
                })

   return vuls 



def check_sensitive_info(url):
    vuls = []

    try:
        resp = requests.get(url, timeout=5)
    except RequestException:
        return []
    
    html = resp.text
    lower_html = html.lower()

    # ---- 1) E-MAILS EXPOSTOS ----
    email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    emails = re.findall(email_pattern, html)
    emails_unicos = list(set(emails))

    if emails_unicos:
        exemplo = emails_unicos[0]  # pega um e-mail como exemplo
        vuls.append({
            "tipo": "sensitive_info",
            "severidade": "media",
            "url": url,
            "detalhe": f"E-mails expostos na página (exemplo: {exemplo})"
        })

    # ---- 2) CPF EXPOSTO ----
    cpf_pattern_formatado = r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"
    cpf_pattern_simples   = r"\b\d{11}\b"

    if re.search(cpf_pattern_formatado, html) or re.search(cpf_pattern_simples, html):
        vuls.append({
            "tipo": "sensitive_info",
            "severidade": "alta",
            "url": url,
            "detalhe": "Possível CPF exposto na página"
        })

    # ---- 3) CHAVES / SEGREDOS ----
    key_indicators = [
        "aws_access_key_id",
        "aws_secret_access_key",
        "begin rsa private key",
        "begin openvpn static key",
        "begin openssh private key",
        "api_key",
        "apikey",
        "x-api-key",
        "bearer "
    ]

    tem_segredo = False
    for indicador in key_indicators:
        if indicador in lower_html:
            tem_segredo = True
            break

    if tem_segredo:
        vuls.append({
            "tipo": "sensitive_info",
            "severidade": "alta",
            "url": url,
            "detalhe": "Possível chave ou segredo sensível exposto no código da página"
        })

    return vuls

def generate_report(vuls, output_file, url, nmap_result=None):
     report = {
        "alvo": url,
        "data": datetime.now().isoformat(),
        "total_vulnerabilidades": len(vuls),
        "vulnerabilidades": [
            {
                "tipo": v["tipo"],
                "severidade": v["severidade"],
                "url": v["url"],
                "detalhe": v["detalhe"],
            }
            for v in vuls
        ],
    }

     if nmap_result is not None:
        report["nmap"] = nmap_result

     with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)


def run_nmap_scan(url):
    """
    Executa um nmap -F no host extraído da URL e retorna um dicionário
    com o resultado (para ser incluído no relatório JSON).
    """
    parsed = urlparse(url)
    host = parsed.hostname or url  # se não conseguir extrair, usa a própria string

    try:
        result = subprocess.run(
            ["nmap", "-F", host],          # -F = fast scan (portas mais comuns)
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0:
            return {
                "host": host,
                "command": f"nmap -F {host}",
                "output": result.stdout
            }
        else:
            return {
                "host": host,
                "command": f"nmap -F {host}",
                "error": result.stderr or f"nmap retornou código {result.returncode}"
            }

    except FileNotFoundError:
        # nmap não instalado ou não está no PATH
        return {
            "host": host,
            "error": "Nmap não encontrado. Verifique se está instalado e no PATH."
        }
    except Exception as e:
        return {
            "host": host,
            "error": f"Erro ao executar nmap: {e}"
        }

def run_scan(url, output):
    vuls = []
    vuls += check_injection(url)
    vuls += check_xss(url)
    vuls += check_csrf(url)
    vuls += check_directory_tranversal(url)
    vuls += check_file_inclusion(url)
    vuls += check_sensitive_info(url)

    # roda nmap no host
    nmap_result = run_nmap_scan(url)

    generate_report(vuls, output, url, nmap_result)



def main():
    if len(sys.argv) != 3:
        print("Uso: python scanner.py LINK out.txt")
        sys.exit(1)
    else:
        url = sys.argv[1]
        output_name = sys.argv[2]
        base_name = os.path.splitext(output_name)[0]
        json_file = base_name + ".json"

        run_scan(url, json_file)


if __name__ == "__main__":
    main()
