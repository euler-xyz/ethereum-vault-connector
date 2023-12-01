# Using Certora Mutate

To run `certoraMutate` for this project, execute the following command depending on which property one wants to run mutation testing agains. 

There currently are 4 manual mutants per property. 
Note: The flag --prover_version master is required until fix for https://certora.atlassian.net/browse/CERT-4160 is released.

## Property 2
> certoraMutate --prover_conf certora/conf/authentication/EVC_Prop2_setOperator.conf --mutation_conf certora/mutate/conf/MutateProp2.conf --prover_version master --server production

Link to pre-generated mutation testing report: https://mutation-testing.certora.com/?id=416582c8-5642-4715-b589-a544f2840b58&anonymousKey=be0634a6-0164-4ca8-8c5a-5927e583fbec

## Property 5
> certoraMutate --prover_conf certora/conf/authentication/EVC_Prop5_onlyOneController.conf --mutation_conf certora/mutate/conf/MutateProp5.conf --prover_version master --server production

Link to pre-generated mutation testing report: https://mutation-testing.certora.com/?id=e7809cc8-36dd-476b-b282-7eac7cdddfa6&anonymousKey=54e00651-bd48-449e-b6bc-c6924aab9822

## Property 24
> certoraMutate --prover_conf certora/conf/authentication/EVC_Prop24_onlyEVCCallsCriticalMethod.conf --mutation_conf certora/mutate/conf/MutateProp24.conf --prover_version master --server production

Link to pre-generated mutation testing report: https://mutation-testing.certora.com/?id=82627d48-04b2-49c0-928a-0ca1b9139a5c&anonymousKey=c8adf8ed-b740-4a45-8533-f3b5c5003e3d