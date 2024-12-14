import os
import subprocess

def check_sudoers():
    sudoers_path = "/etc/sudoers"
    if os.path.exists(sudoers_path):
        try:
            with open(sudoers_path, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if "NOPASSWD" in line:
                        print(f"[ALERTA] Configuración insegura en sudoers (NO requiere contraseña): {line.strip()}")
                    if "ALL" in line and "ALL" not in line.strip().split(" ")[0]:
                        print(f"[ALERTA] Privilegios elevados para usuario en sudoers: {line.strip()}")
        except Exception as e:
            print(f"[ERROR] No se pudo leer el archivo sudoers: {e}")
    else:
        print("[INFO] El archivo /etc/sudoers no se encuentra en el sistema.")

def check_suid_binaries():
    print("\n[INFO] Comprobando archivos SUID:")
    try:
        result = subprocess.run('find / -type f -executable -perm -4000 2>/dev/null', shell=True, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        else:
            print("[INFO] No se encontraron archivos SUID en el sistema.")
    except Exception as e:
        print(f"[ERROR] No se pudo ejecutar el comando find: {e}")

def check_world_writable_files():
    print("\n[INFO] Comprobando archivos y directorios escribibles por todos:")
    try:
        result = subprocess.run('find / -type f -perm -0002 2>/dev/null', shell=True, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        else:
            print("[INFO] No se encontraron archivos o directorios escribibles por todos.")
    except Exception as e:
        print(f"[ERROR] No se pudo ejecutar el comando find: {e}")

def check_cron_jobs():
    print("\n[INFO] Comprobando posibles cron jobs con privilegios elevados:")
    cron_dirs = ['/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/', '/etc/cron.monthly/', '/etc/cron.weekly/']
    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            print(f"[INFO] Revisando cron jobs en {cron_dir}:")
            try:
                for filename in os.listdir(cron_dir):
                    with open(os.path.join(cron_dir, filename), 'r') as file:
                        lines = file.readlines()
                        for line in lines:
                            if "root" in line or "sudo" in line:
                                print(f"[ALERTA] Cron job con privilegios elevados: {line.strip()}")
            except Exception as e:
                print(f"[ERROR] No se pudo acceder a {cron_dir}: {e}")

def check_shadow_permissions():
    print("\n[INFO] Comprobando permisos de /etc/shadow:")
    try:
        shadow_permissions = oct(os.stat('/etc/shadow').st_mode)[-3:]
        if shadow_permissions != '000':
            print(f"[ALERTA] Los permisos de /etc/shadow son demasiado permisivos: {shadow_permissions}")
        else:
            print("[INFO] Los permisos de /etc/shadow son correctos.")
    except Exception as e:
        print(f"[ERROR] No se pudo verificar /etc/shadow: {e}")

def check_user_permissions():
    print("\n[INFO] Comprobando usuarios con permisos de root o similares:")
    try:
        result = subprocess.run('cat /etc/passwd', shell=True, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for line in lines:
            if "root" in line or "/bin/bash" in line:
                print(f"[ALERTA] Usuario con permisos de root o shell accesible: {line.strip()}")
    except Exception as e:
        print(f"[ERROR] No se pudo leer /etc/passwd: {e}")

def check_unneeded_services():
    print("\n[INFO] Comprobando servicios innecesarios o inseguros:")
    try:
        result = subprocess.run('systemctl list-units --type=service --state=running', shell=True, capture_output=True, text=True)
        services = result.stdout.splitlines()
        for service in services:
            if "ssh" in service or "telnet" in service:
                print(f"[ALERTA] Servicio inseguro o innecesario en ejecución: {service.strip()}")
    except Exception as e:
        print(f"[ERROR] No se pudo obtener la lista de servicios: {e}")

def check_policykit():
    print("\n[INFO] Comprobando configuraciones de PolicyKit...")
    
    polkit_dir = "/etc/polkit-1/"
    if os.path.exists(polkit_dir):
        try:
            # Buscar archivos de reglas en /etc/polkit-1/rules.d/
            rule_dir = os.path.join(polkit_dir, "rules.d")
            if os.path.exists(rule_dir):
                for rule_file in os.listdir(rule_dir):
                    rule_path = os.path.join(rule_dir, rule_file)
                    with open(rule_path, 'r') as file:
                        lines = file.readlines()
                        for line in lines:
                            if "allow_any" in line or "auth_admin" in line:  # Posibles configuraciones inseguras
                                print(f"[ALERTA] Regla de PolicyKit insegura en {rule_file}: {line.strip()}")
            else:
                print(f"[INFO] No se encontraron reglas en {rule_dir}.")
        except Exception as e:
            print(f"[ERROR] No se pudo leer las reglas de PolicyKit: {e}")
    else:
        print("[INFO] El directorio /etc/polkit-1/ no existe en este sistema.")

def main():
    print("[INFO] Iniciando auditoría de seguridad...\n")
    check_sudoers()
    check_suid_binaries()
    check_world_writable_files()
    check_cron_jobs()
    check_shadow_permissions()
    check_user_permissions()
    check_unneeded_services()
    check_policykit()  # Verificación de PolicyKit

if __name__ == "__main__":
    main()
