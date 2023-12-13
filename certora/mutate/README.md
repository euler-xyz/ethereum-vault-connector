# Using Certora Mutate

To run `certoraMutate` on this project, execute one of following commands. This will run the prover against the original implementation as well as 
automatically and manually created mutants and checks whether the verification still succeeds. 

For the manual mutants the original code has been copied into folder `certora/mutate/mutations/Prop*` and mutate. The mutation location have been annotated by a comment

```
// [CERTORA MUTATE] Manual mutation
```

## Mutations for Property 2
> certoraMutate --prover_conf certora/conf/authentication/EVC_Prop2_setOperator.conf --mutation_conf certora/mutate/conf/MutateProp2.conf --prover_version master --server production

Link to pre-generated mutation testing report:
https://mutation-testing.certora.com/?id=37d87d73-0930-43a9-b870-eec84ea6723a&anonymousKey=3efb336b-a639-4fd9-8ff7-fb79acbc44df

## Mutations for  Property 5
> certoraMutate --prover_conf certora/conf/authentication/EVC_Prop5_onlyOneController.conf --mutation_conf certora/mutate/conf/MutateProp5.conf --prover_version master --server production

Link to pre-generated mutation testing report:
https://mutation-testing.certora.com/?id=e7809cc8-36dd-476b-b282-7eac7cdddfa6&anonymousKey=54e00651-bd48-449e-b6bc-c6924aab9822

## Mutations for Property 24
> certoraMutate --prover_conf certora/conf/authentication/EVC_Prop24_onlyEVCCallsCriticalMethod.conf --mutation_conf certora/mutate/conf/MutateProp24.conf --prover_version master --server production

Link to pre-generated mutation testing report: 
https://mutation-testing.certora.com/?id=82627d48-04b2-49c0-928a-0ca1b9139a5c&anonymousKey=c8adf8ed-b740-4a45-8533-f3b5c5003e3d

## Mutations for Property 25 & 26

Note that mutations for Property 25 and 26 share the same manual mutants. The invariant `topLevelFunctionDontChangeTransientStorage` and the rule `noFunctionChangesExecutionContext` fail on the same mutants. 

> certoraMutate --prover_conf certora/conf/functionality/EVC_Prop25_ResetsTransientStorage.conf --mutation_conf certora/mutate/conf/MutateProp25_26.conf --prover_version master --server production

Link to pre-generated mutation testing report for Prop 25:
https://mutation-testing.certora.com/?id=cedd2fce-111d-4b22-bd1a-795d61d8d131&anonymousKey=7d9fafe4-a1b6-4477-b3a8-2fd059eeb5a9

Link to pre-generated mutation testing report for Prop 26:
https://mutation-testing.certora.com/?id=cedd2fce-111d-4b22-bd1a-795d61d8d131&anonymousKey=7d9fafe4-a1b6-4477-b3a8-2fd059eeb5a9


## Mutations for Property 27

> certoraMutate --prover_conf certora/conf/authentication/EVC_Prop27_setAccountOwnerSandboxed.conf --mutation_conf certora/mutate/conf/MutateProp27.conf --prover_version master --server production

Link to pre-generated mutation testing report:
https://mutation-testing.certora.com/?id=b487ec5d-60dc-4c78-a801-3ee40cd8620f&anonymousKey=ab5f3b69-5c63-425b-a9ce-6bbeeaf29278

The manual mutants are written per property and are found in the directory `certora/mutate/mutations`. 
Note: The flag --prover_version master is required until fix for https://certora.atlassian.net/browse/CERT-4160 is released.

