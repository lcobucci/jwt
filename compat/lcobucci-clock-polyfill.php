<?php

namespace Lcobucci\Clock;

use DateTimeImmutable;
use DateTimeZone;
use function interface_exists;

if (! interface_exists(Clock::class)) {
    interface Clock
    {
        /** @return DateTimeImmutable */
        public function now();
    }

    final class FrozenClock implements Clock
    {
        /** @var DateTimeImmutable */
        private $now;

        public function __construct(DateTimeImmutable $now)
        {
            $this->now = $now;
        }

        /** @return self */
        public static function fromUTC()
        {
            return new self(new DateTimeImmutable('now', new DateTimeZone('UTC')));
        }

        public function setTo(DateTimeImmutable $now)
        {
            $this->now = $now;
        }

        public function now()
        {
            return $this->now;
        }
    }

    final class SystemClock implements Clock
    {
        /** @var DateTimeZone */
        private $timezone;

        public function __construct(DateTimeZone $timezone)
        {
            $this->timezone = $timezone;
        }

        /** @return self */
        public static function fromUTC()
        {
            return new self(new DateTimeZone('UTC'));
        }

        /** @return self */
        public static function fromSystemTimezone()
        {
            return new self(new DateTimeZone(date_default_timezone_get()));
        }

        public function now()
        {
            return new DateTimeImmutable('now', $this->timezone);
        }
    }
}
