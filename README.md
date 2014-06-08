Clase-PHP-Encriptacion
======================

Clase PHP que contiene funciones para la encriptación y desencriptación de strings.

Podrás encontrar más información en: http://angelbelchite.esy.es/programacion/clase-php-encriptar-desencriptar-cadenas/

Modo de Uso
===========

Para encriptar una cadena y que siempre se genere la misma string encriptada:

```php
<?php

	$security = new Security();

	// Encriptar

		echo $security->encrypt('string', 'key', 1);

	// Desencriptar

		echo $security->decrypt('EncriptedString', 'key', 1);

?>
```

Para encriptar una cadena y que se generen diferentes strings encriptadas:

```php
<?php

	$security = new Security();

	// Encriptar

		echo $security->encrypt('string', 'key', 2);

	// Desencriptar

		echo $security->decrypt('EncriptedString', 'key', 2);

?>
```
