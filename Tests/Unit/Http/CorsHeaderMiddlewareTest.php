<?php
declare(strict_types=1);

namespace Flowpack\Cors\Tests\Unit\Http;

use Flowpack\Cors\Http\CorsHeaderMiddleware;
use Lmc\HttpConstants\Header;
use Neos\Utility\ObjectAccess;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use UnexpectedValueException;

#[CoversClass(CorsHeaderMiddleware::class)]
class CorsHeaderMiddlewareTest extends TestCase
{
    private CorsHeaderMiddleware $middleware;
    private readonly ServerRequestInterface&MockObject $requestMock;
    private readonly ResponseInterface&MockObject $responseMock;
    private readonly RequestHandlerInterface&MockObject $handlerMock;
    private readonly LoggerInterface&MockObject $logger;

    /**
     * @throws Exception
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->middleware = new CorsHeaderMiddleware();
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->responseMock = $this->createMock(ResponseInterface::class);
        $this->handlerMock = $this->createMock(RequestHandlerInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);

        ObjectAccess::setProperty($this->middleware, 'enabled', true, true);
        ObjectAccess::setProperty($this->middleware, 'logger', $this->logger, true);

        $this->handlerMock->expects($this->once())->method('handle')->willReturn($this->responseMock);
    }

    public function testMiddlewareIsNotEnabled(): void
    {
        ObjectAccess::setProperty($this->middleware, 'enabled', false, true);

        $this->responseMock->expects($this->never())->method('withHeader');

        $this->middleware->process($this->requestMock, $this->handlerMock);
    }

    public function testMiddlewarePreflightWithConfig(): void
    {
        $this->injectConfiguration();
        $this->requestMock->expects($this->once())->method('getMethod')->willReturn('OPTIONS');
        $this->requestMock->expects($this->atLeastOnce())->method('getHeader')->willReturnCallback(function (string $value) {
            return match ($value) {
                Header::ORIGIN => ['https://google.com'],
                Header::ACCESS_CONTROL_REQUEST_METHOD => ['GET'],
                Header::ACCESS_CONTROL_REQUEST_HEADERS => [],
                default => throw new UnexpectedValueException(),
            };
        });

        $this->responseMock->expects($this->exactly(5))->method('withHeader')->willReturnSelf();

        $this->middleware->process($this->requestMock, $this->handlerMock);
    }

    public function testMiddlewarePreflightWithWildcardConfig(): void
    {
        $this->injectWildCardConfiguration();
        $this->requestMock->expects($this->atLeastOnce())->method('getMethod')->willReturn('OPTIONS');
        $this->requestMock->expects($this->atLeastOnce())->method('getHeader')->willReturnCallback(function (string $value) {
            return match ($value) {
                Header::ORIGIN => ['https://google.com'],
                Header::ACCESS_CONTROL_REQUEST_METHOD => ['GET'],
                Header::ACCESS_CONTROL_REQUEST_HEADERS => [],
                default => throw new UnexpectedValueException(),
            };
        });

        $this->responseMock->expects($this->exactly(4))->method('withHeader')->willReturnSelf();

         $this->middleware->process($this->requestMock, $this->handlerMock);
    }

    public function testMiddlewareActualRequestWithConfig(): void
    {
        $this->injectConfiguration();
        $this->requestMock->expects($this->atLeastOnce())->method('getMethod')->willReturn('POST');
        $this->requestMock->expects($this->atLeastOnce())->method('getHeader')->willReturnCallback(function (string $value) {
            return match ($value) {
                Header::ORIGIN => ['https://google.com'],
                Header::ACCESS_CONTROL_REQUEST_HEADERS => [],
                default => throw new UnexpectedValueException(),
            };
        });

        $this->responseMock->expects($this->exactly(4))->method('withHeader')->willReturnSelf();

        $this->middleware->process($this->requestMock, $this->handlerMock);
    }

    public function testMiddlewareActualRequestWithWildcardConfig(): void
    {
        $this->injectWildCardConfiguration();
        $this->requestMock->expects($this->atLeastOnce())->method('getMethod')->willReturn('POST');
        $this->requestMock->expects($this->atLeastOnce())->method('getHeader')->willReturnCallback(function (string $value) {
            return match ($value) {
                Header::ORIGIN => ['https://google.com'],
                Header::ACCESS_CONTROL_REQUEST_HEADERS => [],
                default => throw new UnexpectedValueException(),
            };
        });

        $this->responseMock->expects($this->exactly(4))->method('withHeader')->willReturnSelf();

        $this->middleware->process($this->requestMock, $this->handlerMock);
    }

    public function testMiddlewareActualRequestWithWildcardOrigin(): void
    {
        $this->injectConfiguration();
        ObjectAccess::setProperty(
            $this->middleware,
            'allowedOrigins',
            [
                0 => '*.google.com',
            ],
            true
        );
        $this->requestMock->expects($this->atLeastOnce())->method('getMethod')->willReturn('POST');
        $this->requestMock->expects($this->atLeastOnce())->method('getHeader')->willReturnCallback(function (string $value) {
            return match ($value) {
                Header::ORIGIN => ['https://drive.google.com'],
                Header::ACCESS_CONTROL_REQUEST_HEADERS => [],
                default => throw new UnexpectedValueException(),
            };
        });

        $this->responseMock->expects($this->exactly(4))->method('withHeader')->willReturnSelf();

        $this->middleware->process($this->requestMock, $this->handlerMock);
    }

    public function testMiddlewareActualRequestWithNotAllowedOrigin(): void
    {
        $this->injectConfiguration();
        ObjectAccess::setProperty(
            $this->middleware,
            'allowedOrigins',
            [
                0 => '*.google.com',
            ],
            true
        );
        $this->requestMock->expects($this->atLeastOnce())->method('getMethod')->willReturn('POST');
        $this->requestMock->expects($this->atLeastOnce())->method('getHeader')->willReturnCallback(function (string $value) {
            return match ($value) {
                Header::ORIGIN => ['https://test.de'],
                Header::ACCESS_CONTROL_REQUEST_HEADERS => [],
                default => throw new UnexpectedValueException(),
            };
        });

        $this->responseMock->expects($this->never())->method('withHeader')->willReturnSelf();

        $this->logger->expects($this->exactly(2))->method('debug');

        $this->middleware->process($this->requestMock, $this->handlerMock);
    }

    private function injectConfiguration(): void
    {
        ObjectAccess::setProperty(
            $this->middleware,
            'allowedOrigins',
            [
                0 => 'https://google.com',
            ],
            true
        );
        ObjectAccess::setProperty(
            $this->middleware,
            'allowedMethods',
            [
                0 => 'GET',
                1 => 'POST',
            ],
            true
        );
        ObjectAccess::setProperty(
            $this->middleware,
            'exposedHeaders',
            ['Custom-Header'],
            true
        );
        ObjectAccess::setProperty(
            $this->middleware,
            'allowCredentials',
            true,
            true,
        );
        ObjectAccess::setProperty(
            $this->middleware,
            'maxAge',
            60,
            true
        );
    }

    private function injectWildCardConfiguration(): void
    {
        ObjectAccess::setProperty(
            $this->middleware,
            'allowedOrigins',
            [
                0 => '*',
            ],
            true
        );
        ObjectAccess::setProperty(
            $this->middleware,
            'allowedMethods',
            [
                0 => 'GET',
                1 => 'POST',
            ],
            true
        );
        ObjectAccess::setProperty(
            $this->middleware,
            'exposedHeaders',
            ['Custom-Header'],
            true
        );
        ObjectAccess::setProperty(
            $this->middleware,
            'allowCredentials',
            false,
            true,
        );
        ObjectAccess::setProperty(
            $this->middleware,
            'maxAge',
            60,
            true
        );
    }
}
