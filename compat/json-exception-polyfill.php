<?php

if (PHP_VERSION_ID < 70300 && ! class_exists('JsonException')) {
    class JsonException extends Exception
    {
    }
}
