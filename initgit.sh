rm -rf .git
git init
git branch -M test
git add Documents/web/
git commit -m "add all"
git remote add origin git@github.com:BalkamFR/testrecupdata.git
git push --set-upstream origin test -f
rm -rf .git
rm -rf testrecupdata