# Simulador de Examen Interactivo (Temática Matrix)

Este programa Python crea un simulador de examen interactivo con una interfaz de línea de comandos (CLI).  El programa está diseñado con una temática inspirada en la película *The Matrix*, ofreciendo una experiencia de usuario inmersiva.

## Características

*   **Preguntas de Opción Múltiple:** El examen consiste en preguntas de opción múltiple (tipo test) con cuatro opciones (A, B, C, D).
*   **Cuestionario Personalizable:** Las preguntas y respuestas se almacenan en una lista de diccionarios dentro del propio código, lo que permite modificar, añadir o eliminar preguntas fácilmente.
*   **Selección Aleatoria de Preguntas:** El programa selecciona un número determinado de preguntas al azar de un conjunto más amplio, lo que garantiza que cada examen sea diferente.
*   **Número de Preguntas Configurable:** El usuario puede elegir cuántas preguntas quiere responder al inicio del examen (dentro de los límites del cuestionario).
*   **Interfaz Temática (Matrix):**  Toda la interfaz del programa, incluyendo los mensajes de bienvenida, despedida, felicitación y ánimo, está inspirada en la película *The Matrix*, creando una experiencia más atractiva.
*   **Validación de Entrada:** El programa verifica que el usuario introduzca una opción válida (A, B, C o D) y le pide que lo intente de nuevo si introduce un valor incorrecto.
*   **Retroalimentación Detallada:** Al final del examen, el programa muestra:
    *   La puntuación total (aciertos / total de preguntas).
    *   Un mensaje de felicitación o ánimo, también temático de *The Matrix*.
    *   Si hay errores, muestra las preguntas falladas junto con sus *explicaciones* correspondientes.
*   **Código Limpio y Modular:** El código está organizado en funciones claras y bien definidas (`presentacion`, `solicitar_numero_preguntas`, `realizar_test`, `mostrar_resultados`), lo que facilita su lectura, comprensión y modificación.
*   **Sin Limpieza de Pantalla**: El programa permite ver todo el "historial" del test gracias a que no limpia la pantalla tras cada pregunta.

## Requisitos

*   Python 3.x (compatible con cualquier versión de Python 3).
*   No se requieren bibliotecas externas (solo se usan `random` y `os`, que son parte de la biblioteca estándar de Python).

## Instalación

1.  **Clonar el repositorio (o descargar el código):**

    ```bash
    git clone <URL del repositorio>  # Si usas Git
    # O descarga el archivo .zip y descomprímelo
    ```

2.  **Navegar al directorio del proyecto:**

    ```bash
    cd <nombre del directorio>
    ```

## Uso

1.  **Ejecutar el script:**

    ```bash
    python examen.py  # O python3 examen.py, dependiendo de tu sistema
    ```

2.  **Seguir las instrucciones en pantalla:**
    *   El programa te dará la bienvenida con un mensaje temático.
    *   Te preguntará cuántas preguntas quieres responder.  Introduce un número válido (entre 1 y el número total de preguntas en el cuestionario).
    *   Te preguntará si quieres empezar el test (S/N).
    *   Responde a cada pregunta introduciendo la letra de la opción correcta (A, B, C o D).  El programa no distingue entre mayúsculas y minúsculas.
    *   Al final del test, verás tus resultados y las explicaciones de las preguntas que hayas fallado.

## Personalización del Cuestionario

Para modificar el cuestionario, edita la lista `cuestionario` directamente en el código del archivo `examen.py`.  Cada pregunta es un diccionario con la siguiente estructura:

```python
{
    "pregunta": "Texto de la pregunta",
    "opciones": ["A) Opción 1", "B) Opción 2", "C) Opción 3", "D) Opción 4"],
    "respuesta": "B",  # SOLO la LETRA de la opción correcta (A, B, C o D)
    "explicacion": "Explicación de la respuesta correcta."
}
