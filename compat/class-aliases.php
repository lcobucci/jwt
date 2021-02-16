<?php

class_exists(\Lcobucci\JWT\Token\Plain::class, false) || class_alias(\Lcobucci\JWT\Token::class, \Lcobucci\JWT\Token\Plain::class);
class_exists(\Lcobucci\JWT\Token\Signature::class, false) || class_alias(\Lcobucci\JWT\Signature::class, \Lcobucci\JWT\Token\Signature::class);
