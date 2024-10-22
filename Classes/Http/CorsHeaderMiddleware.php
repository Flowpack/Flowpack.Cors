<?php

declare(strict_types=1);

namespace Flowpack\Cors\Http;

use Lmc\HttpConstants\Header;
use Neos\Flow\Annotations as Flow;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

class CorsHeaderMiddleware implements MiddlewareInterface
{
    /**
     * @Flow\InjectConfiguration("enabled")
     */
    protected bool $enabled = false;

    /**
     * @Flow\InjectConfiguration("allowedOrigins")
     *
     * @var string[]
     */
    protected array $allowedOrigins = [];

    /**
     * @Flow\InjectConfiguration("allowedHeaders")
     * @var string[]
     */
    protected array $allowedHeaders = [];

    /**
     * @Flow\InjectConfiguration("exposedHeaders")
     * @var string[]
     */
    protected array $exposedHeaders = [];

    /**
     * @Flow\InjectConfiguration("allowedMethods")
     * @var string[]
     */
    protected array $allowedMethods = [];

    /**
     * @Flow\InjectConfiguration("allowCredentials")
     */
    protected bool $allowCredentials = false;

    /**
     * @Flow\InjectConfiguration("maxAge")
     */
    protected int $maxAge = 0;

    /**
     * @Flow\Inject
     */
    protected LoggerInterface $logger;

    /** @var string[]  */
    private array $allowedWildcardOrigins = [];
    /** @var string[]  */
    private array $allowedPlainOrigins = [];
    private bool $allowedOriginsAll = false;
    private bool $allowedHeadersAll = false;

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$this->enabled) {
            return $handler->handle($request);
        }

        $this->initializeConfiguration();

        $response = $handler->handle($request);
        $method = $request->getMethod();

        // method type is not options, return early
        if ($method == 'OPTIONS') {
            $this->logger->debug('CORS Component: Preflight request');
            return $this->handlePreflight($request, $response);
        }
        return $this->handleRequest($request, $response);
    }

    private function initializeConfiguration(): void
    {
        foreach ($this->allowedOrigins as $origin) {
            $origin = strtolower($origin);
            if ($origin === '*') {
                $this->allowedOriginsAll = true;
                break;
            } elseif (($i = strpos($origin, '*')) !== false) {
                $this->allowedWildcardOrigins[] = [substr($origin, 0, $i), substr($origin, $i + 1)];
            } else {
                $this->allowedPlainOrigins[] = $origin;
            }
        }

        // Origin is always appended as some browsers will always request for this header at preflight
        if (!in_array(Header::ORIGIN, $this->allowedHeaders, true)) {
            $this->allowedHeaders[] = Header::ORIGIN;
        }

        foreach ($this->allowedHeaders as $headerKey) {
            if ($headerKey === '*') {
                $this->allowedHeadersAll = true;
                break;
            }
        }

        foreach ($this->exposedHeaders as &$exposedHeader) {
            $exposedHeader = strtolower($exposedHeader);
        }

        foreach ($this->allowedHeaders as &$allowedHeader) {
            $allowedHeader = strtolower($allowedHeader);
        }

        foreach ($this->allowedMethods as &$method) {
            $method = strtoupper($method);
        }

        $this->logger->debug('CORS Component: Init', ['allowedHeaders' => $this->allowedHeaders]);
    }

    private function handlePreflight(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $headersToAdd = [];
        /**
         * Always set Vary headers, see
         * https://github.com/rs/cors/issues/10 and
         * https://github.com/rs/cors/commit/dbdca4d95feaa7511a46e6f1efb3b3aa505bc43f#commitcomment-12352001
         */
        $response = $response->withHeader(
            'Vary', [Header::ORIGIN, Header::ACCESS_CONTROL_REQUEST_METHOD, Header::ACCESS_CONTROL_REQUEST_HEADERS]
        );

        $origin = $request->getHeader(Header::ORIGIN)[0] ?? '';

        if ($origin === '') {
            $this->logger->debug('Preflight aborted: empty Origin header.');

            return $response;
        }

        if (!$this->isOriginAllowed($origin)) {

            $this->logger->debug("Preflight aborted: origin $origin not allowed");

            return $response;
        }

        $requestMethod = $request->getHeader('Access-Control-Request-Method')[0] ?? '';
        if (!$this->isMethodAllowed($requestMethod)) {

            $this->logger->debug("Preflight aborted: method $requestMethod not allowed");

            return $response;
        }

        $headerList = $request->getHeader('Access-Control-Request-Headers');
        if (!$this->areHeadersAllowed($headerList)) {

            $headerList = implode(', ', $headerList);
            $this->logger->debug("Preflight aborted: headers $headerList not allowed.");

            return $response;
        }

        if ($this->allowedOriginsAll && !$this->allowCredentials) {
            $headersToAdd[Header::ACCESS_CONTROL_ALLOW_ORIGIN] = '*';
        } else {
            $headersToAdd[Header::ACCESS_CONTROL_ALLOW_ORIGIN] = $origin;
        }

        // Spec says: Since the list of methods can be unbounded, simply returning the method indicated
        // by Access-Control-Request-Method (if supported) can be enough

        $headersToAdd[Header::ACCESS_CONTROL_ALLOW_METHODS] = strtoupper($requestMethod);

        if ($headerList !== []) {
            // Spec says: Since the list of headers can be unbounded, simply returning supported headers
            // from Access-Control-Request-Headers can be enough
            $headersToAdd[Header::ACCESS_CONTROL_ALLOW_HEADERS] = implode(', ', $headerList);
        }

        if ($this->allowCredentials) {
            $headersToAdd[Header::ACCESS_CONTROL_ALLOW_CREDENTIALS] = 'true';
        }

        if ($this->maxAge > 0) {
            $headersToAdd[Header::ACCESS_CONTROL_MAX_AGE] = (string)$this->maxAge;
        }

        $this->logger->debug('Preflight response headers', ['headers' => $response->getHeaders(),]);

        foreach ($headersToAdd as $header => $value) {
            $response = $response->withHeader($header, $value);
        }

        return $response;
    }

    private function handleRequest(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $method = $request->getMethod();

        $headersToAdd = [];

        if ($method === 'OPTIONS') {

            $this->logger->debug('Actual request no headers added: method == OPTIONS');

            return $response;
        }

        $origin = $request->getHeader(Header::ORIGIN)[0] ?? '';
        $headersToAdd['Vary'] = Header::ORIGIN;
        if ($origin === '') {

            $this->logger->debug('Actual request no headers added: missing origin');

            return $response;
        }

        if (!$this->isOriginAllowed($origin)) {

            $this->logger->debug("Actual request no headers added: origin $origin not allowed");

            return $response;
        }

        // Note that spec does define a way to specifically disallow a simple method like GET or
        // POST. Access-Control-Allow-Methods is only used for pre-flight requests and the
        // spec doesn't instruct to check the allowed methods for simple cross-origin requests.
        // We think it's a nice feature to be able to have control on those methods though.
        if (!$this->isMethodAllowed($method)) {

            $this->logger->debug("Actual request no headers added: method $method not allowed");

            return $response;
        }

        if ($this->allowedOriginsAll && !$this->allowCredentials) {
            $headersToAdd[Header::ACCESS_CONTROL_ALLOW_ORIGIN] = '*';
        } else {
            $headersToAdd[Header::ACCESS_CONTROL_ALLOW_ORIGIN] = $origin;
        }

        if ($this->exposedHeaders !== []) {
            $headersToAdd['Access-Control-Expose-Headers'] = implode(', ', $this->exposedHeaders);
        }

        $headersToAdd[Header::ACCESS_CONTROL_ALLOW_CREDENTIALS] = 'true';

        $this->logger->debug('Actual response added headers', ['headers' => $response->getHeaders()]);
        foreach ($headersToAdd as $header => $value) {
            $response = $response->withHeader($header, $value);
        }

        return $response;
    }

    private function isOriginAllowed(string $origin): bool
    {
        if ($this->allowedOriginsAll) {
            return true;
        }
        $origin = strtolower($origin);
        if (in_array($origin, $this->allowedPlainOrigins, true)) {
            return true;
        }
        foreach ($this->allowedWildcardOrigins as $allowedWildCardOrigin) {
            $matches = strlen($origin) >= strlen($allowedWildCardOrigin[0]) + strlen(
                    $allowedWildCardOrigin[1]
                ) && str_starts_with(
                    $origin,
                    $allowedWildCardOrigin[0]
                ) && strpos($origin, $allowedWildCardOrigin[1]) === strlen($origin) - strlen($allowedWildCardOrigin[1]);
            if ($matches) {
                return true;
            }
        }

        return false;
    }

    private function isMethodAllowed(string $method): bool
    {
        if ($this->allowedMethods === []) {
            // If no method allowed, always return false, even for preflight request
            return false;
        }
        $method = strtoupper($method);
        if ($method === 'OPTIONS') {
            // Always allow preflight requests
            return true;
        }

        return in_array($method, $this->allowedMethods, true);
    }

    /**
     * @param string[] $headers
     */
    private function areHeadersAllowed(array $headers): bool
    {
        if ($this->allowedHeadersAll || $this->allowedHeaders === []) {
            return true;
        }
        foreach ($headers as $header) {
            if (!in_array($header, $this->allowedHeaders, true)) {
                return false;
            }
        }

        return true;
    }
}
