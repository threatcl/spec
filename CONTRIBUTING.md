# How to contribute

Hi! I'm really happy you want to help out with `threatcl`. At this early stage, the best way to get started is to [Submit an Issue](https://github.com/threatcl/threatcl/issues) or [Submit a PR](https://github.com/threatcl/threatcl/pulls).

I've been doing most of the work in the [dev](https://github.com/threatcl/threatcl/tree/dev) branch, and this is probably the best place to start looking at making changes.

## Testing

There are a bunch of `_test.go` files. To run the test suite:

```
$ make test
```

Alternatively, if you want to run `go vet` instead:

```
$ make vet
```

## Submitting changes

Please send a [GitHub Pull Request to threatcl](https://github.com/threatcl/spec/pulls) with a clear list of what you've done (read more about [pull requests](http://help.github.com/pull-requests/)). When you send a pull request, we will love you forever if you include tests as well. We can always use more test coverage. Please follow our coding conventions (below) and make sure all of your commits are atomic (one feature per commit).

Always write a clear log message for your commits. One-line messages are fine for small changes, but bigger changes should look like this:

    $ git commit -m "fix: A brief summary of the commit
    > 
    > A paragraph describing what changed and its impact."

## Coding conventions

All Go code should be formatted according to https://pkg.go.dev/golang.org/x/tools/cmd/goimports. This can be validated by running:

## Releasing

This module is a key dependency of https://github.com/threatcl/threatcl, while this repo doesn't have any automated pipelines, it is expected to follow go module git tagging.

To release a new version:
* Update all the references to the version number to the new version, particularly the VERSION const in [config](config.go) file.
* Update the [CHANGELOG](CHANGELOG.md)
* Once the main branch has been merged and updated and all the [actions](https://github.com/threatcl/threatcl/actions) are complete - this is basically setup to release "dev" release (without docker)
* Once that's complete and you're ready to do the primary release, you tag
* `git tag -a vN.N.N -m 'vN.N.N'`
* `git push --tags`
* Finally, you'll need to adjust the go.mod in http://github.com/threatcl/threatcl

Thanks,
Christian @xntrik Frichot
