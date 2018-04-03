<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware.Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use HWI\Bundle\OAuthBundle\Security\OAuthErrorHandler;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\HttpFoundation\Request as HttpRequest;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * GitLabResourceOwner.
 *
 * @author Indra Gunawan <hello@indra.my.id>
 */
class OzwilloResourceOwner extends GenericOAuth2ResourceOwner
{
    /**
     * {@inheritdoc}
     */
    protected $paths = array(
        'identifier' => 'sub',
        'nickname' => 'nickname',
        'realname' => 'name',
        'email' => 'email',
    );

    public function configure()
    {
        $subdomain = str_replace('.'. $this->domain, '' , $_SERVER['HTTP_HOST']);

        $collectivite = $this->entityManager->getRepository('SesileMainBundle:Collectivite')->findOneByDomain($subdomain);
        if ($collectivite) {
            $this->client_id = $collectivite->getOzwillo()->getClientId();
            $this->client_secret = $collectivite->getOzwillo()->getClientSecret();
        } else {
            $this->client_id = $this->options['client_id'];
            $this->client_secret = $this->options['client_secret'];
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults(array(
            'authorization_url' => 'https://accounts.ozwillo.com/a/auth',
            'access_token_url' => 'https://accounts.ozwillo.com/a/token',
            'infos_url' => 'https://accounts.ozwillo.com/a/userinfo',

            'scope' => 'email openid profile',
            'use_basic_authorization' => true,
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationUrl($redirectUri, array $extraParameters = array())
    {
        return parent::getAuthorizationUrl($redirectUri, array_replace($extraParameters, array('client_id' => $this->client_id)));
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken(HttpRequest $request, $redirectUri, array $extraParameters = array())
    {
        OAuthErrorHandler::handleOAuthError($request);

        $parameters = array_merge(array(
            'code' => $request->query->get('code'),
            'grant_type' => 'authorization_code',
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri' => $redirectUri,
        ), $extraParameters);

        $response = $this->doGetTokenRequest($this->options['access_token_url'], $parameters);
        $response = $this->getResponseContent($response);

        $this->validateResponseContent($response);

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function refreshAccessToken($refreshToken, array $extraParameters = array())
    {
        $parameters = array_merge(array(
            'refresh_token' => $refreshToken,
            'grant_type' => 'refresh_token',
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
        ), $extraParameters);

        $response = $this->doGetTokenRequest($this->options['access_token_url'], $parameters);
        $response = $this->getResponseContent($response);

        $this->validateResponseContent($response);

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeToken($token)
    {
        if (!isset($this->options['revoke_token_url'])) {
            throw new AuthenticationException('OAuth error: "Method unsupported."');
        }

        $parameters = [
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
        ];

        $response = $this->httpRequest($this->normalizeUrl($this->options['revoke_token_url'], array('token' => $token)), $parameters, array(), 'DELETE');

        return 200 === $response->getStatusCode();
    }

    /**
     * {@inheritdoc}
     */
    protected function doGetTokenRequest($url, array $parameters = array())
    {

        if (!$this->options['use_basic_authorization']) {
            return $this->httpRequest($url, http_build_query($parameters, '', '&'));
        }

        $authPreHash = $this->client_id.':'.$this->client_secret;
        $authHeader = array(
            'Authorization' => 'Basic '.base64_encode($authPreHash)
        );

        return $this->httpRequest(
            $url,
            http_build_query($parameters, '', '&'),
            $authHeader
        );
    }
}
