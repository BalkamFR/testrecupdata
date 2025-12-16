rm -rf .git
git init
git add Documents/web/
git commit -m "add all"
git branch -M main
git remote add origin git@github.com:BalkamFR/testrecupdata.git
git push --set-upstream origin main -f

