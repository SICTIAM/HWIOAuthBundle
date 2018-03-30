Step 2x: Setup Ozwillo
======================
First you will have to register your application on Ozwillo. Check out the
documentation for more information: http://doc.ozwillo.com/.

Next configure a resource owner of type `ozwillo` with appropriate
`client_id` & `client_secret`.

```yaml
# app/config/config.yml

hwi_oauth:
    resource_owners:
        any_name:
            type:                ozwillo
            client_id:           <client_id>
            client_secret:       <client_secret>
```

We need to support many organizations and each of them have a `client_id` and `client_secret`. We store them in database.

The `client_id` and `client_secret` are define in `OAuth/ResourceOwner/OzwilloResourceOwner.php` in `configure` function.
Perhaps you have to update this function to define your own logic.

When you're done. Continue by configuring the security layer or go back to
setup more resource owners.

- [Step 2: Configuring resource owners (Facebook, GitHub, Google, Windows Live and others](../2-configuring_resource_owners.md)
- [Step 3: Configuring the security layer](../3-configuring_the_security_layer.md).
