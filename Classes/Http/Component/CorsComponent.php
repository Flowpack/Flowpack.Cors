<?php
namespace Flowpack\Cors\Http\Component;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Component\ComponentChain;
use Neos\Flow\Http\Component\ComponentContext;
use Neos\Flow\Http\Headers;
use Neos\Utility\Arrays;

class CorsComponent implements \Neos\Flow\Http\Component\ComponentInterface {

    /**
     * @Flow\InjectConfiguration("allowedOrigins")
     * @var string[]
     */
    protected $allowedOrigins;

    /**
     * @Flow\InjectConfiguration("allowedMethods")
     * @var string[]
     */
    protected $allowedMethods;

    /**
     * @Flow\InjectConfiguration("allowedHeaders")
     * @var string[]
     */
    protected $allowedHeaders;

    /**
     * @Flow\InjectConfiguration("exposedHeaders")
     * @var string[]
     */
    protected $exposedHeaders;

    /**
     * @Flow\InjectConfiguration("allowCredentials")
     * @var bool
     */
    protected $allowCredentials = false;

    /**
     * @Flow\InjectConfiguration("maxAge")
     * @var int
     */
    protected $maxAge = 0;

    /**
     * @Flow\InjectConfiguration("optionsPassthrough")
     * @var false
     */
    protected $optionsPassthrough = false;

    /**
     * @Flow\InjectConfiguration("debug")
     * @var false
     */
    protected $debug = false;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Log\SystemLoggerInterface
     */
    protected $systemLogger;

    // Internal properties

    /**
     * @var bool
     */
    protected $allowedOriginsAll = false;

    /**
     * @var string[]
     */
    protected $allowedPlainOrigins = [];

    /**
     * @var string[]
     */
    protected $allowedWildcardOrigins = [];

    /**
     * @var bool
     */
    protected $allowedHeadersAll = false;

    public function initializeObject() {
        // TODO Move conversion to static compilation, does not need to happen during runtime
        $this->allowedWildcardOrigins = [];
        foreach ($this->allowedOrigins as $origin) {
            // Normalize
            $origin = strtolower($origin);
            if ($origin === '*') {
                $this->allowedOriginsAll = true;
                break;
            } else if (($i = strpos($origin, '*')) !== false) {
                $this->allowedWildcardOrigins[] = [substr($origin, 0, $i), substr($origin, $i+1)];
            } else {
                $this->allowedPlainOrigins[] = $origin;
            }
        }

        $this->allowedHeadersAll = false;
        // Origin is always appended as some browsers will always request for this header at preflight
        if (!in_array('Origin', $this->allowedHeaders, true)) {
            $this->allowedHeaders[] = 'Origin';
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

        if ($this->debug) {
            $this->systemLogger->log('CORS Component: Init', LOG_DEBUG, [
                'allowedHeaders' => $this->allowedHeaders
            ]);
        }
    }

    public function handle(ComponentContext $componentContext)
    {
        $request = $componentContext->getHttpRequest();
        if ($request->getMethod() === 'OPTIONS') {
            if ($this->debug) {
                $this->systemLogger->log('CORS Component: Preflight request', LOG_DEBUG);
            }
            $this->handlePreflight($componentContext);
            if (!$this->optionsPassthrough) {
                $componentContext->setParameter(ComponentChain::class, 'cancel', true);
            }
        } else {
            if ($this->debug) {
                $this->systemLogger->log('CORS Component: Actual request', LOG_DEBUG);
            }
            $this->handleActualRequest($componentContext);
        }

    }

    protected function handlePreflight(ComponentContext $componentContext)
    {
        $request = $componentContext->getHttpRequest();
        $response = $componentContext->getHttpResponse();

        $origin = (string)$request->getHeader('Origin');

        // Always set Vary headers
        // see https://github.com/rs/cors/issues/10,
        //     https://github.com/rs/cors/commit/dbdca4d95feaa7511a46e6f1efb3b3aa505bc43f#commitcomment-12352001
        $request->setHeader('Vary', ['Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers']);

        if ($origin === '') {
            if ($this->debug) {
                $this->systemLogger->log('    Preflight aborted: empty Origin header', LOG_DEBUG);
            }
            return;
        }

        if (!$this->isOriginAllowed($origin)) {
            if ($this->debug) {
                $this->systemLogger->log(sprintf('    Preflight aborted: origin "%s" not allowed', $origin), LOG_DEBUG);
            }
            return;
        }

        $requestMethod = $request->getHeader('Access-Control-Request-Method');
        if (!$this->isMethodAllowed($requestMethod)) {
            if ($this->debug) {
                $this->systemLogger->log(sprintf('    Preflight aborted: method "%s" not allowed', $origin), LOG_DEBUG);
            }
            return;
        }

        $headerList = $request->getHeader("Access-Control-Request-Headers");
        $requestHeaders = $this->parseHeaderList($headerList);
        if (!$this->areHeadersAllowed($requestHeaders)) {
            if ($this->debug) {
                $this->systemLogger->log(sprintf('    Preflight aborted: headers "%s" not allowed', $headerList), LOG_DEBUG);
            }
            return;
        }

        if ($this->allowedOriginsAll && !$this->allowCredentials) {
            $response->setHeader('Access-Control-Allow-Origin', '*');
        } else {
            $response->setHeader('Access-Control-Allow-Origin', $origin);
        }

        // Spec says: Since the list of methods can be unbounded, simply returning the method indicated
        // by Access-Control-Request-Method (if supported) can be enough
        $response->setHeader('Access-Control-Allow-Methods', strtoupper($requestMethod));

        if ($requestHeaders !== []) {
            // Spec says: Since the list of headers can be unbounded, simply returning supported headers
            // from Access-Control-Request-Headers can be enough
            $response->setHeader('Access-Control-Allow-Headers', implode(', ', $requestHeaders));
        }

        if ($this->allowCredentials) {
            $response->setHeader('Access-Control-Allow-Credentials', 'true');
        }

        if ($this->maxAge > 0) {
            $response->setHeader('Access-Control-Max-Age', $this->maxAge);
        }

        if ($this->debug) {
            $this->systemLogger->log('    Preflight response headers', LOG_DEBUG, [
                'headers' => $response->getHeaders()->getAll()
            ]);
        }
    }

    protected function handleActualRequest(ComponentContext $componentContext)
    {
        $request = $componentContext->getHttpRequest();
        $response = $componentContext->getHttpResponse();

        $method = $request->getMethod();
        if ($method === 'OPTIONS') {
            if ($this->debug) {
                $this->systemLogger->log('    Actual request no headers added: method == OPTIONS', LOG_DEBUG);
            }
            return;
        }

        $origin = $request->getHeader('Origin');
        $response->setHeader('Vary', 'Origin', false);
        if ($origin === '') {
            if ($this->debug) {
                $this->systemLogger->log('    Actual request no headers added: missing origin', LOG_DEBUG);
            }
            return;
        }

        if (!$this->isOriginAllowed($origin)) {
            if ($this->debug) {
                $this->systemLogger->log(sprintf('    Actual request no headers added: origin "%s" not allowed', $origin), LOG_DEBUG);
            }
            return;
        }

        // Note that spec does define a way to specifically disallow a simple method like GET or
        // POST. Access-Control-Allow-Methods is only used for pre-flight requests and the
        // spec doesn't instruct to check the allowed methods for simple cross-origin requests.
        // We think it's a nice feature to be able to have control on those methods though.
        if (!$this->isMethodAllowed($method)) {
            if ($this->debug) {
                $this->systemLogger->log(sprintf('    Actual request no headers added: method "%s" not allowed', $method), LOG_DEBUG);
            }
            return;
        }

        if ($this->allowedOriginsAll && !$this->allowCredentials) {
            $response->setHeader('Access-Control-Allow-Origin', '*');
        } else {
            $response->setHeader('Access-Control-Allow-Origin', $origin);
        }

        if ($this->exposedHeaders !== []) {
            $response->setHeader('Access-Control-Expose-Headers', implode(', ', $this->exposedHeaders));
        }

        if ($this->allowCredentials) {
            $response->setHeader('Access-Control-Allow-Credentials', 'true');
        }

        if ($this->debug) {
            $this->systemLogger->log('    Actual response added headers', LOG_DEBUG, [
                'headers' => $response->getHeaders()->getAll()
            ]);
        }
    }

    /**
     * @param string $origin
     * @return bool
     */
    protected function isOriginAllowed($origin)
    {
        if ($this->allowedOriginsAll) {
            return true;
        }
        $origin = strtolower($origin);
        foreach ($this->allowedPlainOrigins as $o) {
            if ($origin === $o) {
                return true;
            }
        }
        foreach ($this->allowedWildcardOrigins as $w) {
            // TODO Test!!!
            $matches = strlen($origin) >= strlen($w[0]) + strlen($w[1]) && strpos($origin, $w[0]) === 0 && strpos($origin, $w[1]) === strlen($origin) - strlen($w[1]);
            if ($matches) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $method
     * @return bool
     */
    protected function isMethodAllowed($method)
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
        foreach ($this->allowedMethods as $m) {
            if ($method === $m) {
                return true;
            }
        }
        return false;
    }

    /**
     * Tokenize + normalize a string containing a list of headers
     *
     * @param string $headerList
     * @return string[]
     */
    protected function parseHeaderList($headerList)
    {
        $headerList = strtolower($headerList);
        return Arrays::trimExplode(',', $headerList, true);
    }

    /**
     * @param string[] $headers
     * @return bool
     */
    protected function areHeadersAllowed(array $headers)
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