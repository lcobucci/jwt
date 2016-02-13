<?php
namespace Lcobucci\JWT\Validation;

interface ResultsInterface
{
    public function valid(): bool;

    public function errors(): array;
}
