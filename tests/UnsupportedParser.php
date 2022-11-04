<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use DateTimeInterface;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;

final class UnsupportedParser implements Parser
{
    public function parse(string $jwt): Token
    {
        return new class () implements Token {
            public function headers(): DataSet
            {
                return new DataSet([], '');
            }

            public function isPermittedFor(string $audience): bool
            {
                return false;
            }

            public function isIdentifiedBy(string $id): bool
            {
                return false;
            }

            public function isRelatedTo(string $subject): bool
            {
                return false;
            }

            public function hasBeenIssuedBy(string ...$issuers): bool
            {
                return false;
            }

            public function hasBeenIssuedBefore(DateTimeInterface $now): bool
            {
                return false;
            }

            public function isMinimumTimeBefore(DateTimeInterface $now): bool
            {
                return false;
            }

            public function isExpired(DateTimeInterface $now): bool
            {
                return false;
            }

            public function toString(): string
            {
                return '';
            }
        };
    }
}
