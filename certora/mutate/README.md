# Using Certora Mutate

To run `certoraMutate` for this project, execute the following command depending on which property one wants to run mutation testing agains. 

There currently are 4 manual mutants per property. 
Note: The flag --prover_version master is required until fix for https://certora.atlassian.net/browse/CERT-4160 is released.

## Property 2
> certoraMutate --prover_conf certora/conf/authentication/EVC_Prop2_setOperator.conf --mutation_conf certora/mutate/conf/MutateProp2.conf --prover_version master --server production

Link to pre-generated mutation testing report: https://mutation-testing.certora.com/?id=37d87d73-0930-43a9-b870-eec84ea6723a&anonymousKey=3efb336b-a639-4fd9-8ff7-fb79acbc44df

## Property 5
> certoraMutate --prover_conf certora/conf/authentication/EVC_Prop5_onlyOneController.conf --mutation_conf certora/mutate/conf/MutateProp5.conf --prover_version master --server production

Link to pre-generated mutation testing report: https://mutation-testing.certora.com/?id=e7809cc8-36dd-476b-b282-7eac7cdddfa6&anonymousKey=54e00651-bd48-449e-b6bc-c6924aab9822

## Property 24
> certoraMutate --prover_conf certora/conf/authentication/EVC_Prop24_onlyEVCCallsCriticalMethod.conf --mutation_conf certora/mutate/conf/MutateProp24.conf --prover_version master --server production

Link to pre-generated mutation testing report: https://mutation-testing.certora.com/?id=82627d48-04b2-49c0-928a-0ca1b9139a5c&anonymousKey=c8adf8ed-b740-4a45-8533-f3b5c5003e3d