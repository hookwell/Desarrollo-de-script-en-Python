import re  # Importar el módulo para trabajar con expresiones regulares
import sys  # Importar el módulo para acceder a argumentos de línea de comandos
from collections import defaultdict  # Importa defaultdict para crear diccionarios con valores predeterminados

def extract_failed_ips(log_path):
    """
    Extrae las direcciones IP de los intentos fallidos de un archivo de registro.
    
    Args:
        log_path (str): Ruta al archivo de registro a analizar
        
    Returns:
        defaultdict: Diccionario con las IPs como claves y la cantidad de intentos fallidos como valores
    """
    # Definir un patrón de expresión regular para encontrar direcciones IP
    ip_pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
    # Inicializa un diccionario que tendrá 0 como valor predeterminado
    failed_ips = defaultdict(int)

    try:
        # Intentar abrir y leer el archivo de registro
        with open(log_path, 'r') as file:
            for line in file:
                # Busca la palabra 'failed' en cada línea (sin distinguir mayúsculas/minúsculas)
                if 'failed' in line.lower():
                    # Busca un patrón de IP en la línea
                    match = ip_pattern.search(line)
                    if match:
                        # Si encuentra una IP, la extrae y aumenta su contador
                        ip = match.group(1)
                        failed_ips[ip] += 1
        return failed_ips
    except FileNotFoundError:
        # Manejar el error si el archivo no existe
        print(f"[ERROR] Archivo no encontrado: {log_path}")
    except Exception as e:
        # Manejar cualquier otro error que pueda ocurrir
        print(f"[ERROR] Ocurrió un error: {e}")
    # Devuelver un diccionario vacío en caso de error
    return {}

def main():
    """
    Función principal que procesa los argumentos y muestra los resultados.
    """
    # Verificar que se haya proporcionado exactamente un argumento (la ruta del archivo)
    if len(sys.argv) != 2:
        print("Uso: python count_failed_logins.py <archivo.log>")
        sys.exit(1)  # Sale del programa con código de error 1

    # Obtiener la ruta del archivo de los argumentos
    log_path = sys.argv[1]
    # Llamar a la función para extraer las IPs de intentos fallidos
    failed_attempts = extract_failed_ips(log_path)

    # Si se encontraron intentos fallidos, muestra los resultados
    if failed_attempts:
        print("\nIntentos fallidos por IP:")
        # Ordenar las IPs por número de intentos (de mayor a menor)
        for ip, count in sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip}: {count} intentos")
    else:
        print("No se encontraron intentos fallidos.")

# Verificar si el script se está ejecutando directamente (no importado como módulo)
if __name__ == "__main__":
    main()  # Llama a la función principal
