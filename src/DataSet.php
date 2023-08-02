<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

interface DataSet
{
    /** @param non-empty-string $name */
    public function get(string $name, mixed $default = null): mixed;

    /** @param non-empty-string $name */
    public function has(string $name): bool;

    /** @return array<non-empty-string, mixed> */
    public function all(): array;

    public function toString(): string;
}
