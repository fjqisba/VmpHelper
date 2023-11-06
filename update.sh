git checkout --orphan newBranch
git add -A
git commit -am "commit message"
git branch -D main
git branch -m main
git push -f origin main